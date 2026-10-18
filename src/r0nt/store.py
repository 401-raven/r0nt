"""Repository storage (chunks + manifests on disk) and SQLite witness DB.

SPEC §6:
  - Chunks:    ``repo/chunks/<first2>/<hash>``  (content-addressed)
  - Manifests: ``repo/manifests/<backup_id>.json``  (atomic writes)
  - Witness DB: SQLite with HMAC-SHA256 row MACs, schema versioning.
"""

from __future__ import annotations

import hashlib
import hmac as hmac_mod
import json
import sqlite3
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from r0nt.manifest import canonical_json, manifest_hash, manifest_to_bytes, manifest_from_bytes

SCHEMA_VERSION = 3

_CREATE_TABLES_SQL = """\
CREATE TABLE IF NOT EXISTS metadata (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS manifests (
    backup_id          TEXT    PRIMARY KEY,
    sequence_number    INTEGER NOT NULL UNIQUE,
    manifest_hash      TEXT    NOT NULL,
    prev_manifest_hash TEXT,
    root_hash          TEXT    NOT NULL,
    created_at         TEXT    NOT NULL,
    signature          TEXT    NOT NULL,
    row_mac            TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS verification_history (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    run_at         TEXT    NOT NULL,
    backup_id      TEXT,
    result         TEXT    NOT NULL,
    finding_count  INTEGER NOT NULL,
    findings_json  TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS anchors (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at      TEXT    NOT NULL,
    batch_root      TEXT    NOT NULL,
    leaf_count      INTEGER NOT NULL,
    backend         TEXT    NOT NULL,
    proof           BLOB,
    status          TEXT    NOT NULL CHECK(status IN ('pending', 'confirmed', 'failed', 'skipped')),
    confirmed_at    TEXT,
    row_mac         TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS anchor_members (
    anchor_id       INTEGER NOT NULL REFERENCES anchors(id),
    sequence_number INTEGER NOT NULL,
    manifest_hash   TEXT    NOT NULL,
    leaf            TEXT    NOT NULL,
    merkle_path     TEXT    NOT NULL,
    row_mac         TEXT    NOT NULL,
    PRIMARY KEY (anchor_id, sequence_number)
);

CREATE TABLE IF NOT EXISTS restore_tests (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    run_at       TEXT    NOT NULL,
    backup_id    TEXT    NOT NULL,
    status       TEXT    NOT NULL CHECK(status IN ('passed', 'failed', 'cancelled')),
    sample_count INTEGER NOT NULL,
    failed_count INTEGER NOT NULL,
    details_json TEXT    NOT NULL,
    row_mac      TEXT    NOT NULL
);
"""


# =========================================================================
# Chunk store
# =========================================================================

class ChunkStore:
    """Content-addressable chunk storage on the filesystem."""

    def __init__(self, repo_path: Path) -> None:
        self.chunks_dir = repo_path / 'chunks'
        self.chunks_dir.mkdir(parents=True, exist_ok=True)

    def _path(self, chunk_hash: str) -> Path:
        return self.chunks_dir / chunk_hash[:2] / chunk_hash

    def write_chunk(self, chunk_hash: str, data: bytes) -> bool:
        """Write a chunk.  Returns ``True`` if new, ``False`` if deduplicated."""
        path = self._path(chunk_hash)
        if path.exists():
            return False
        path.parent.mkdir(parents=True, exist_ok=True)
        # Atomic write: temp → rename
        with tempfile.NamedTemporaryFile(
            dir=path.parent, delete=False, mode='wb',
        ) as tmp:
            tmp.write(data)
            tmp_path = Path(tmp.name)
        tmp_path.rename(path)
        return True

    def read_chunk(self, chunk_hash: str) -> bytes:
        """Read a chunk and verify its hash matches the filename.

        Raises ``FileNotFoundError`` or ``ValueError`` on failure.
        """
        path = self._path(chunk_hash)
        if not path.exists():
            raise FileNotFoundError(f"Chunk not found: {chunk_hash}")
        data = path.read_bytes()
        actual = hashlib.sha256(data).hexdigest()
        if not hmac_mod.compare_digest(actual, chunk_hash):
            raise ValueError(
                f"Chunk integrity failure: expected {chunk_hash}, got {actual}"
            )
        return data

    def has_chunk(self, chunk_hash: str) -> bool:
        return self._path(chunk_hash).exists()

    def list_chunks(self) -> list[str]:
        chunks: list[str] = []
        if not self.chunks_dir.exists():
            return chunks
        for prefix_dir in sorted(self.chunks_dir.iterdir()):
            if prefix_dir.is_dir():
                for chunk_file in sorted(prefix_dir.iterdir()):
                    if chunk_file.is_file():
                        chunks.append(chunk_file.name)
        return chunks


# =========================================================================
# Manifest store
# =========================================================================

class ManifestStore:
    """Manifest JSON files on disk with atomic writes."""

    def __init__(self, repo_path: Path) -> None:
        self.manifests_dir = repo_path / 'manifests'
        self.manifests_dir.mkdir(parents=True, exist_ok=True)

    def write_manifest(self, manifest: dict) -> None:
        """Write a manifest file atomically."""
        bid = manifest['backup_id']
        target = self.manifests_dir / f'{bid}.json'
        data = manifest_to_bytes(manifest)
        with tempfile.NamedTemporaryFile(
            dir=self.manifests_dir, delete=False, mode='wb', suffix='.tmp',
        ) as tmp:
            tmp.write(data)
            tmp_path = Path(tmp.name)
        tmp_path.rename(target)

    def read_manifest(self, backup_id: str) -> dict:
        path = self.manifests_dir / f'{backup_id}.json'
        if not path.exists():
            raise FileNotFoundError(f"Manifest not found: {backup_id}")
        return manifest_from_bytes(path.read_bytes())

    def list_manifests(self) -> list[str]:
        """Return all ``backup_id`` values with manifests on disk."""
        ids: list[str] = []
        if not self.manifests_dir.exists():
            return ids
        for f in sorted(self.manifests_dir.iterdir()):
            if f.is_file() and f.suffix == '.json':
                ids.append(f.stem)
        return ids

    def load_all_manifests(self) -> list[dict]:
        return [self.read_manifest(bid) for bid in self.list_manifests()]

    def delete_manifest(self, backup_id: str) -> None:
        """Delete a manifest file.  (Intended for tests / attack scripts.)"""
        path = self.manifests_dir / f'{backup_id}.json'
        if path.exists():
            path.unlink()


# =========================================================================
# Witness DB
# =========================================================================

class WitnessDB:
    """SQLite witness database with HMAC-protected rows.

    The witness DB is the trust anchor when external anchoring is absent.
    Each row in the ``manifests`` table carries an HMAC-SHA256 MAC so
    that offline tampering can be detected.
    """

    def __init__(self, db_path: Path, mac_key: bytes) -> None:
        """Open (or create) the witness DB at *db_path*.

        Args:
            db_path: Filesystem path to the SQLite file.
            mac_key: 32-byte key for HMAC-SHA256 row MACs.
        """
        self.db_path = db_path
        self.mac_key = mac_key
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(db_path))
        self.conn.row_factory = sqlite3.Row
        self._init_schema()

    # -- schema -------------------------------------------------------------

    def _init_schema(self) -> None:
        cur = self.conn.cursor()
        cur.execute(
            "SELECT name FROM sqlite_master "
            "WHERE type='table' AND name='metadata'"
        )
        if cur.fetchone() is None:
            cur.executescript(_CREATE_TABLES_SQL)
            cur.execute(
                "INSERT INTO metadata (key, value) VALUES ('schema_version', ?)",
                (str(SCHEMA_VERSION),),
            )
            self.conn.commit()
        else:
            cur.execute("SELECT value FROM metadata WHERE key='schema_version'")
            row = cur.fetchone()
            if row is None:
                raise ValueError(
                    "Witness DB metadata exists but schema_version is missing"
                )
            version = int(row['value'])
            if version > SCHEMA_VERSION:
                raise ValueError(
                    f"Witness DB schema v{version} is newer than supported "
                    f"v{SCHEMA_VERSION} — cannot downgrade"
                )
            if version < SCHEMA_VERSION:
                self._migrate(version)

    def _migrate(self, from_version: int) -> None:
        """Run forward migrations."""
        cur = self.conn.cursor()
        if from_version < 2:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS anchors (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at      TEXT    NOT NULL,
                    batch_root      TEXT    NOT NULL,
                    leaf_count      INTEGER NOT NULL,
                    backend         TEXT    NOT NULL,
                    proof           BLOB,
                    status          TEXT    NOT NULL CHECK(status IN ('pending', 'confirmed', 'failed', 'skipped')),
                    confirmed_at    TEXT,
                    row_mac         TEXT    NOT NULL
                );
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS anchor_members (
                    anchor_id       INTEGER NOT NULL REFERENCES anchors(id),
                    sequence_number INTEGER NOT NULL,
                    manifest_hash   TEXT    NOT NULL,
                    leaf            TEXT    NOT NULL,
                    merkle_path     TEXT    NOT NULL,
                    row_mac         TEXT    NOT NULL,
                    PRIMARY KEY (anchor_id, sequence_number)
                );
            """)
            cur.execute(
                "UPDATE metadata SET value = '2' WHERE key = 'schema_version'"
            )
            self.conn.commit()

        if from_version < 3:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS restore_tests (
                    id           INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_at       TEXT    NOT NULL,
                    backup_id    TEXT    NOT NULL,
                    status       TEXT    NOT NULL CHECK(status IN ('passed', 'failed', 'cancelled')),
                    sample_count INTEGER NOT NULL,
                    failed_count INTEGER NOT NULL,
                    details_json TEXT    NOT NULL,
                    row_mac      TEXT    NOT NULL
                );
            """)
            cur.execute(
                "UPDATE metadata SET value = '3' WHERE key = 'schema_version'"
            )
            self.conn.commit()

    # -- row MAC ------------------------------------------------------------

    def _compute_row_mac(
        self,
        backup_id: str,
        sequence_number: int,
        manifest_hash_val: str,
        prev_manifest_hash: str | None,
        root_hash: str,
    ) -> str:
        """HMAC-SHA256 over the critical fields of a manifests row."""
        data = canonical_json({
            "backup_id": backup_id,
            "manifest_hash": manifest_hash_val,
            "prev_manifest_hash": prev_manifest_hash,
            "root_hash": root_hash,
            "sequence_number": sequence_number,
        })
        return hmac_mod.new(self.mac_key, data, hashlib.sha256).hexdigest()

    def verify_row_mac(self, row: dict) -> bool:
        """Return ``True`` if the row's MAC is valid."""
        expected = self._compute_row_mac(
            backup_id=row['backup_id'],
            sequence_number=row['sequence_number'],
            manifest_hash_val=row['manifest_hash'],
            prev_manifest_hash=row['prev_manifest_hash'],
            root_hash=row['root_hash'],
        )
        return hmac_mod.compare_digest(expected, row['row_mac'])

    def _compute_anchor_row_mac(
        self,
        created_at: str,
        batch_root: str,
        leaf_count: int,
        backend: str,
        status: str,
    ) -> str:
        """HMAC-SHA256 over critical fields of an anchors row."""
        data = canonical_json({
            "backend": backend,
            "batch_root": batch_root,
            "created_at": created_at,
            "leaf_count": leaf_count,
            "status": status,
        })
        return hmac_mod.new(self.mac_key, data, hashlib.sha256).hexdigest()

    def verify_anchor_row_mac(self, row: dict) -> bool:
        """Return ``True`` if the anchor row's MAC is valid."""
        expected = self._compute_anchor_row_mac(
            created_at=row['created_at'],
            batch_root=row['batch_root'],
            leaf_count=row['leaf_count'],
            backend=row['backend'],
            status=row['status'],
        )
        return hmac_mod.compare_digest(expected, row['row_mac'])

    def _compute_anchor_member_row_mac(
        self,
        anchor_id: int,
        sequence_number: int,
        manifest_hash_val: str,
        leaf: str,
        merkle_path: str,
    ) -> str:
        """HMAC-SHA256 over critical fields of an anchor_members row."""
        data = canonical_json({
            "anchor_id": anchor_id,
            "leaf": leaf,
            "manifest_hash": manifest_hash_val,
            "merkle_path": merkle_path,
            "sequence_number": sequence_number,
        })
        return hmac_mod.new(self.mac_key, data, hashlib.sha256).hexdigest()

    def verify_anchor_member_row_mac(self, row: dict) -> bool:
        """Return ``True`` if the anchor_members row's MAC is valid."""
        expected = self._compute_anchor_member_row_mac(
            anchor_id=row['anchor_id'],
            sequence_number=row['sequence_number'],
            manifest_hash_val=row['manifest_hash'],
            leaf=row['leaf'],
            merkle_path=row['merkle_path'],
        )
        return hmac_mod.compare_digest(expected, row['row_mac'])

    def _compute_restore_test_row_mac(
        self,
        run_at: str,
        backup_id: str,
        status: str,
        sample_count: int,
        failed_count: int,
    ) -> str:
        """HMAC-SHA256 over critical fields of a restore_tests row."""
        data = canonical_json({
            "backup_id": backup_id,
            "failed_count": failed_count,
            "run_at": run_at,
            "sample_count": sample_count,
            "status": status,
        })
        return hmac_mod.new(self.mac_key, data, hashlib.sha256).hexdigest()

    def verify_restore_test_row_mac(self, row: dict) -> bool:
        """Return ``True`` if the restore_tests row's MAC is valid."""
        expected = self._compute_restore_test_row_mac(
            run_at=row['run_at'],
            backup_id=row['backup_id'],
            status=row['status'],
            sample_count=row['sample_count'],
            failed_count=row['failed_count'],
        )
        return hmac_mod.compare_digest(expected, row['row_mac'])

    # -- write --------------------------------------------------------------

    def record_manifest(self, manifest: dict) -> None:
        """Insert a manifest record into the witness DB."""
        m_hash = manifest_hash(manifest)
        bid = manifest['backup_id']
        seq = manifest['sequence_number']
        prev = manifest.get('prev_manifest_hash')
        root = manifest['root_hash']
        sig = manifest['signature']
        created_at = manifest.get('created_at') or datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')

        row_mac = self._compute_row_mac(
            backup_id=bid,
            sequence_number=seq,
            manifest_hash_val=m_hash,
            prev_manifest_hash=prev,
            root_hash=root,
        )

        self.conn.execute(
            "INSERT INTO manifests "
            "(backup_id, sequence_number, manifest_hash, prev_manifest_hash, "
            " root_hash, created_at, signature, row_mac) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (bid, seq, m_hash, prev, root, created_at, sig, row_mac),
        )
        self.conn.commit()

    # -- read ---------------------------------------------------------------

    def get_all_records(self) -> list[dict]:
        """All manifest rows, ordered by ``sequence_number``."""
        cur = self.conn.execute(
            "SELECT * FROM manifests ORDER BY sequence_number"
        )
        return [dict(row) for row in cur.fetchall()]

    def get_latest_record(self) -> dict | None:
        cur = self.conn.execute(
            "SELECT * FROM manifests ORDER BY sequence_number DESC LIMIT 1"
        )
        row = cur.fetchone()
        return dict(row) if row else None

    def get_next_sequence_number(self) -> int:
        latest = self.get_latest_record()
        return 1 if latest is None else latest['sequence_number'] + 1

    def get_prev_manifest_hash(self) -> str | None:
        latest = self.get_latest_record()
        return None if latest is None else latest['manifest_hash']

    # -- verification history -----------------------------------------------

    def record_verification(
        self,
        backup_id: str | None,
        result: str,
        findings: list[dict],
    ) -> None:
        run_at = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        self.conn.execute(
            "INSERT INTO verification_history "
            "(run_at, backup_id, result, finding_count, findings_json) "
            "VALUES (?, ?, ?, ?, ?)",
            (run_at, backup_id, result, len(findings), json.dumps(findings)),
        )
        self.conn.commit()

    # -- anchors ------------------------------------------------------------

    def record_anchor(
        self,
        batch_root: str,
        leaf_count: int,
        backend: str,
        proof: bytes | None,
        status: str,
        created_at: str | None = None,
        confirmed_at: str | None = None,
    ) -> int:
        """Insert an anchor record with row_mac and return the generated anchor id."""
        if created_at is None:
            created_at = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        row_mac = self._compute_anchor_row_mac(
            created_at=created_at,
            batch_root=batch_root,
            leaf_count=leaf_count,
            backend=backend,
            status=status,
        )
        cur = self.conn.execute(
            "INSERT INTO anchors "
            "(created_at, batch_root, leaf_count, backend, proof, status, confirmed_at, row_mac) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (created_at, batch_root, leaf_count, backend, proof, status, confirmed_at, row_mac),
        )
        self.conn.commit()
        return cur.lastrowid

    def update_anchor_status(
        self,
        anchor_id: int,
        status: str,
        proof: bytes | None = None,
        confirmed_at: str | None = None,
    ) -> None:
        """Update anchor status, proof and confirmed_at, recomputing the row_mac."""
        cur = self.conn.execute("SELECT * FROM anchors WHERE id = ?", (anchor_id,))
        row = cur.fetchone()
        if not row:
            raise ValueError(f"Anchor with id {anchor_id} not found")
        created_at = row['created_at']
        batch_root = row['batch_root']
        leaf_count = row['leaf_count']
        backend = row['backend']
        current_proof = row['proof'] if proof is None else proof
        conf_time = row['confirmed_at'] if confirmed_at is None else confirmed_at

        row_mac = self._compute_anchor_row_mac(
            created_at=created_at,
            batch_root=batch_root,
            leaf_count=leaf_count,
            backend=backend,
            status=status,
        )
        self.conn.execute(
            "UPDATE anchors "
            "SET status = ?, proof = ?, confirmed_at = ?, row_mac = ? "
            "WHERE id = ?",
            (status, current_proof, conf_time, row_mac, anchor_id),
        )
        self.conn.commit()

    def record_anchor_member(
        self,
        anchor_id: int,
        sequence_number: int,
        manifest_hash_val: str,
        leaf: str,
        merkle_path: str,
    ) -> None:
        """Insert a member manifest of an anchor batch with row_mac."""
        row_mac = self._compute_anchor_member_row_mac(
            anchor_id=anchor_id,
            sequence_number=sequence_number,
            manifest_hash_val=manifest_hash_val,
            leaf=leaf,
            merkle_path=merkle_path,
        )
        self.conn.execute(
            "INSERT INTO anchor_members "
            "(anchor_id, sequence_number, manifest_hash, leaf, merkle_path, row_mac) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (anchor_id, sequence_number, manifest_hash_val, leaf, merkle_path, row_mac),
        )
        self.conn.commit()

    def get_unanchored_manifests(self) -> list[dict]:
        """Return manifest records not yet included in any pending or confirmed anchor batch."""
        cur = self.conn.execute("""
            SELECT * FROM manifests
            WHERE sequence_number NOT IN (
                SELECT am.sequence_number
                FROM anchor_members am
                JOIN anchors a ON am.anchor_id = a.id
                WHERE a.status IN ('pending', 'confirmed')
            )
            ORDER BY sequence_number ASC
        """)
        return [dict(r) for r in cur.fetchall()]

    def get_all_anchors(self) -> list[dict]:
        """All anchor rows ordered by id ascending."""
        cur = self.conn.execute("SELECT * FROM anchors ORDER BY id ASC")
        return [dict(r) for r in cur.fetchall()]

    def get_anchor(self, anchor_id: int) -> dict | None:
        cur = self.conn.execute("SELECT * FROM anchors WHERE id = ?", (anchor_id,))
        row = cur.fetchone()
        return dict(row) if row else None

    def get_anchor_members(self, anchor_id: int) -> list[dict]:
        """All member manifest rows for an anchor ordered by sequence_number."""
        cur = self.conn.execute(
            "SELECT * FROM anchor_members WHERE anchor_id = ? ORDER BY sequence_number ASC",
            (anchor_id,)
        )
        return [dict(r) for r in cur.fetchall()]

    # -- restore test records (migration v3) --------------------------------

    def record_restore_test(
        self,
        backup_id: str,
        status: str,
        sample_count: int,
        failed_count: int,
        details_json: str,
        run_at: str | None = None,
    ) -> int:
        """Record the outcome of a restore test run into the witness DB."""
        if run_at is None:
            run_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        row_mac = self._compute_restore_test_row_mac(
            run_at=run_at,
            backup_id=backup_id,
            status=status,
            sample_count=sample_count,
            failed_count=failed_count,
        )
        cur = self.conn.cursor()
        cur.execute(
            """
            INSERT INTO restore_tests (
                run_at, backup_id, status, sample_count, failed_count, details_json, row_mac
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (run_at, backup_id, status, sample_count, failed_count, details_json, row_mac),
        )
        self.conn.commit()
        return cur.lastrowid

    def get_restore_test_history(self, limit: int = 50) -> list[dict]:
        """Fetch past restore-test history ordered newest first."""
        cur = self.conn.execute(
            "SELECT * FROM restore_tests ORDER BY id DESC LIMIT ?",
            (limit,),
        )
        return [dict(r) for r in cur.fetchall()]

    # -- lifecycle ----------------------------------------------------------

    def close(self) -> None:
        self.conn.close()
