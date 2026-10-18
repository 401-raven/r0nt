import hashlib
from pathlib import Path
import pytest

from r0nt.chunker import hash_chunk
from r0nt.manifest import build_manifest
from r0nt.signing import generate_keypair
from r0nt.store import ChunkStore, ManifestStore, WitnessDB, SCHEMA_VERSION


def test_chunk_store(tmp_path: Path):
    repo = tmp_path / "repo"
    store = ChunkStore(repo)

    data = b"chunk payload"
    chash = hash_chunk(data)

    # First write returns True (new)
    assert store.write_chunk(chash, data) is True
    # Second write returns False (deduplicated)
    assert store.write_chunk(chash, data) is False

    assert store.has_chunk(chash) is True
    assert store.read_chunk(chash) == data
    assert store.list_chunks() == [chash]

    # Tampered chunk detected on read
    chunk_file = repo / "chunks" / chash[:2] / chash
    chunk_file.write_bytes(b"tampered payload")
    with pytest.raises(ValueError, match="Chunk integrity failure"):
        store.read_chunk(chash)

    # Missing chunk
    with pytest.raises(FileNotFoundError):
        store.read_chunk("00" * 32)


def test_manifest_store(tmp_path: Path):
    repo = tmp_path / "repo"
    m_store = ManifestStore(repo)

    priv, pub = generate_keypair()
    m = build_manifest(
        file_results=[],
        skipped_files=[],
        chunk_size=1024,
        prev_manifest_hash=None,
        sequence_number=1,
        private_key=priv,
        public_key=pub,
    )

    m_store.write_manifest(m)
    bid = m["backup_id"]

    assert m_store.list_manifests() == [bid]
    loaded = m_store.read_manifest(bid)
    assert loaded["backup_id"] == bid

    all_m = m_store.load_all_manifests()
    assert len(all_m) == 1
    assert all_m[0]["backup_id"] == bid

    m_store.delete_manifest(bid)
    assert m_store.list_manifests() == []


def test_witness_db_mac_and_history(tmp_path: Path):
    db_path = tmp_path / "witness.sqlite"
    mac_key = b"A" * 32
    wdb = WitnessDB(db_path, mac_key)

    priv, pub = generate_keypair()
    m1 = build_manifest(
        file_results=[],
        skipped_files=[],
        chunk_size=1024,
        prev_manifest_hash=None,
        sequence_number=1,
        private_key=priv,
        public_key=pub,
    )

    wdb.record_manifest(m1)

    records = wdb.get_all_records()
    assert len(records) == 1
    rec = records[0]
    assert rec["backup_id"] == m1["backup_id"]
    assert rec["sequence_number"] == 1
    assert wdb.verify_row_mac(rec) is True

    # Tamper with row: verify_row_mac returns False
    tampered_rec = dict(rec)
    tampered_rec["manifest_hash"] = "deadbeef" * 8
    assert wdb.verify_row_mac(tampered_rec) is False

    # Next sequence number & prev hash
    assert wdb.get_next_sequence_number() == 2
    assert wdb.get_prev_manifest_hash() == rec["manifest_hash"]

    # Verification history recording
    wdb.record_verification(
        backup_id=m1["backup_id"],
        result="clean",
        findings=[],
    )
    cur = wdb.conn.execute("SELECT * FROM verification_history")
    hist = cur.fetchall()
    assert len(hist) == 1
    assert hist[0]["result"] == "clean"
    assert hist[0]["finding_count"] == 0

    wdb.close()


def test_witness_db_newer_schema(tmp_path: Path):
    db_path = tmp_path / "future.sqlite"
    mac_key = b"B" * 32
    wdb = WitnessDB(db_path, mac_key)
    # Set future schema version
    wdb.conn.execute("UPDATE metadata SET value = ? WHERE key = 'schema_version'", (str(SCHEMA_VERSION + 99),))
    wdb.conn.commit()
    wdb.close()

    # Reopening should raise ValueError
    with pytest.raises(ValueError, match="is newer than supported"):
        WitnessDB(db_path, mac_key)
