"""Unit tests for automated restore testing subsystem (SPEC_PHASE3 §3, T-40)."""

from __future__ import annotations

import os
from pathlib import Path
import sqlite3
import threading
import pytest

from r0nt.chunker import scan_source
from r0nt.manifest import build_manifest
from r0nt.restoretest import (
    check_file_health,
    run_restore_test,
    select_sample,
    validate_workdir_safety,
)
from r0nt.signing import generate_keypair
from r0nt.store import ChunkStore, ManifestStore, WitnessDB


def _create_multi_type_backup(tmp_path: Path):
    """Create a backup fixture with various file types: text, JSON, SQLite, PNG, and ZIP."""
    src = tmp_path / "src"
    src.mkdir(parents=True, exist_ok=True)

    # 1. UTF-8 text file
    (src / "document.txt").write_text("Integrity verification for r0nt restore test.", encoding="utf-8")

    # 2. Valid JSON file
    (src / "config.json").write_text('{"app": "r0nt", "enabled": true, "version": 3}', encoding="utf-8")

    # 3. Valid SQLite database
    db_file = src / "test.db"
    conn = sqlite3.connect(str(db_file))
    conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT);")
    conn.execute("INSERT INTO users VALUES (1, 'Alice'), (2, 'Bob');")
    conn.commit()
    conn.close()

    # 4. Valid PNG image header
    png_bytes = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64
    (src / "logo.png").write_bytes(png_bytes)

    # 5. Unknown binary file (should pass on hash match)
    (src / "data.bin").write_bytes(b"\x12\x34\x56\x78" * 32)

    repo = tmp_path / "repo"
    wdb_path = tmp_path / "witness.db"
    priv, pub = generate_keypair()
    wdb = WitnessDB(wdb_path, b"k" * 32)

    file_results, skipped = scan_source(src)
    cs = ChunkStore(repo)
    ms = ManifestStore(repo)

    for fr in file_results:
        for c in fr.chunks:
            cs.write_chunk(c.hash, c.data)

    manifest = build_manifest(
        file_results=file_results,
        skipped_files=skipped,
        chunk_size=1024 * 1024,
        prev_manifest_hash=None,
        sequence_number=1,
        private_key=priv,
        public_key=pub,
    )
    ms.write_manifest(manifest)
    wdb.record_manifest(manifest)

    return src, repo, wdb, manifest


def test_restore_test_clean_pass(tmp_path: Path):
    src, repo, wdb, manifest = _create_multi_type_backup(tmp_path)

    result = run_restore_test(
        manifest=manifest,
        repo_path=repo,
        witness_db=wdb,
        source_paths=[src],
        sample_percent=100.0,
    )

    assert result.status == "passed"
    assert result.exit_code == 0
    assert result.failed_count == 0
    assert result.passed_count == 5
    assert len(result.failures) == 0

    # Ensure working directory was completely cleaned up
    assert not Path(result.workdir).exists()

    # Ensure result was recorded in witness DB
    history = wdb.get_restore_test_history()
    assert len(history) == 1
    assert history[0]["status"] == "passed"
    assert history[0]["sample_count"] == 5
    assert history[0]["failed_count"] == 0
    assert wdb.verify_restore_test_row_mac(history[0]) is True


def test_restore_test_deleted_chunk(tmp_path: Path):
    src, repo, wdb, manifest = _create_multi_type_backup(tmp_path)

    # Pick a file from manifest and delete one of its chunks from repository
    target_file = next(f for f in manifest["files"] if f["path"] == "document.txt")
    chunk_hash = target_file["chunks"][0]
    chunk_path = repo / "chunks" / chunk_hash[:2] / chunk_hash
    chunk_path.unlink()

    result = run_restore_test(
        manifest=manifest,
        repo_path=repo,
        witness_db=wdb,
        source_paths=[src],
        sample_percent=100.0,
    )

    assert result.status == "failed"
    assert result.exit_code == 1
    assert result.failed_count >= 1

    # Verify failure details identify the file and chunk error
    fail = next(f for f in result.failures if f.path == "document.txt")
    assert fail.stage == "chunk_read"
    assert "missing" in fail.reason or "corrupted" in fail.reason

    assert not Path(result.workdir).exists()


def test_restore_test_flipped_byte(tmp_path: Path):
    src, repo, wdb, manifest = _create_multi_type_backup(tmp_path)

    # Corrupt a byte in the chunk store for config.json
    target_file = next(f for f in manifest["files"] if f["path"] == "config.json")
    chunk_hash = target_file["chunks"][0]
    chunk_path = repo / "chunks" / chunk_hash[:2] / chunk_hash

    content = bytearray(chunk_path.read_bytes())
    content[0] ^= 0xFF
    chunk_path.write_bytes(content)

    result = run_restore_test(
        manifest=manifest,
        repo_path=repo,
        witness_db=wdb,
        source_paths=[src],
        sample_percent=100.0,
    )

    assert result.status == "failed"
    assert result.exit_code == 1

    fail = next(f for f in result.failures if f.path == "config.json")
    assert fail.stage == "chunk_read"
    assert "corrupted" in fail.reason or "SHA-256" in fail.reason

    assert not Path(result.workdir).exists()


def test_restore_test_corrupted_zip_fails_type_check(tmp_path: Path):
    """A corrupted zip file that hashes cleanly into the backup fails type check upon restore."""
    src = tmp_path / "src"
    src.mkdir()

    # Create invalid zip bytes (starts with zip header PK\x03\x04 but has truncated/corrupt entries)
    bad_zip_bytes = b"PK\x03\x04" + b"\x00" * 30 + b"INVALID_ZIP_STREAM"
    (src / "corrupted_archive.zip").write_bytes(bad_zip_bytes)

    repo = tmp_path / "repo"
    wdb_path = tmp_path / "witness.db"
    priv, pub = generate_keypair()
    wdb = WitnessDB(wdb_path, b"k" * 32)

    file_results, skipped = scan_source(src)
    cs = ChunkStore(repo)
    ms = ManifestStore(repo)

    for fr in file_results:
        for c in fr.chunks:
            cs.write_chunk(c.hash, c.data)

    manifest = build_manifest(
        file_results=file_results,
        skipped_files=skipped,
        chunk_size=1024 * 1024,
        prev_manifest_hash=None,
        sequence_number=1,
        private_key=priv,
        public_key=pub,
    )
    ms.write_manifest(manifest)
    wdb.record_manifest(manifest)

    # Chunks are authentic and hash matches, but the zip is corrupted
    result = run_restore_test(
        manifest=manifest,
        repo_path=repo,
        witness_db=wdb,
        source_paths=[src],
        sample_percent=100.0,
    )

    assert result.status == "failed"
    assert result.exit_code == 1
    assert result.failed_count == 1

    fail = result.failures[0]
    assert fail.path == "corrupted_archive.zip"
    assert fail.stage == "type_check"
    assert "Zip verification error" in fail.reason or "Corrupted zip" in fail.reason

    assert not Path(result.workdir).exists()


def test_restore_test_workdir_inside_repo_rejected(tmp_path: Path):
    src, repo, wdb, manifest = _create_multi_type_backup(tmp_path)

    # Workdir inside repo
    bad_workdir_repo = repo / "nested_workdir"
    with pytest.raises(ValueError, match="cannot be inside repository"):
        validate_workdir_safety(bad_workdir_repo, repo, [src])

    # Workdir inside source folder
    bad_workdir_src = src / "nested_workdir"
    with pytest.raises(ValueError, match="cannot be inside source folder"):
        validate_workdir_safety(bad_workdir_src, repo, [src])


def test_restore_test_cleanup_on_cancel(tmp_path: Path):
    src, repo, wdb, manifest = _create_multi_type_backup(tmp_path)

    cancel_event = threading.Event()
    cancel_event.set()  # Cancel immediately

    result = run_restore_test(
        manifest=manifest,
        repo_path=repo,
        witness_db=wdb,
        source_paths=[src],
        cancel_event=cancel_event,
    )

    assert result.status == "cancelled"
    assert result.exit_code == 130
    assert not Path(result.workdir).exists()


def test_witness_db_migration_v3_and_row_mac_verification(tmp_path: Path):
    db_path = tmp_path / "v2_test.db"
    mac_key = b"m" * 32

    # Manually create a schema v2 DB
    conn = sqlite3.connect(str(db_path))
    conn.execute("CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT);")
    conn.execute("INSERT INTO metadata VALUES ('schema_version', '2');")
    conn.execute("""
        CREATE TABLE manifests (
            backup_id TEXT PRIMARY KEY, sequence_number INTEGER, manifest_hash TEXT,
            prev_manifest_hash TEXT, root_hash TEXT, created_at TEXT, signature TEXT, row_mac TEXT
        );
    """)
    conn.execute("""
        CREATE TABLE anchors (
            id INTEGER PRIMARY KEY, created_at TEXT, batch_root TEXT, leaf_count INTEGER,
            backend TEXT, proof BLOB, status TEXT, confirmed_at TEXT, row_mac TEXT
        );
    """)
    conn.execute("""
        CREATE TABLE anchor_members (
            anchor_id INTEGER, sequence_number INTEGER, manifest_hash TEXT, leaf TEXT,
            merkle_path TEXT, row_mac TEXT, PRIMARY KEY (anchor_id, sequence_number)
        );
    """)
    conn.commit()
    conn.close()

    # Opening with WitnessDB should automatically migrate v2 -> v3
    wdb = WitnessDB(db_path, mac_key)
    row = wdb.conn.execute("SELECT value FROM metadata WHERE key='schema_version'").fetchone()
    assert int(row[0]) == 3

    # Verify restore_tests table exists
    tables = [r[0] for r in wdb.conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
    assert "restore_tests" in tables

    # Record a test run
    test_id = wdb.record_restore_test(
        backup_id="backup_100",
        status="passed",
        sample_count=10,
        failed_count=0,
        details_json='{"ok": true}',
    )
    assert test_id == 1

    history = wdb.get_restore_test_history()
    assert len(history) == 1
    assert wdb.verify_restore_test_row_mac(history[0]) is True

    # Tamper with the row in SQLite (simulating an attacker modifying test history)
    wdb.conn.execute("UPDATE restore_tests SET status = 'failed' WHERE id = 1")
    wdb.conn.commit()

    tampered_history = wdb.get_restore_test_history()
    assert wdb.verify_restore_test_row_mac(tampered_history[0]) is False


def test_select_sample_logic():
    files = [{"path": f"f_{i}.txt"} for i in range(100)]

    # 1. Default: min(20, 5% of 100 = 5) -> 5
    sample_default = select_sample(files, seed=42)
    assert len(sample_default) == 5

    # 2. Large set default: 1000 files -> 5% is 50, but min(20, 50) -> 20
    large_files = [{"path": f"f_{i}.txt"} for i in range(1000)]
    sample_large = select_sample(large_files, seed=42)
    assert len(sample_large) == 20

    # 3. Explicit count
    sample_explicit = select_sample(files, sample_count=12, seed=42)
    assert len(sample_explicit) == 12

    # 4. Explicit percent (10% of 100 = 10)
    sample_pct = select_sample(files, sample_percent=10.0, seed=42)
    assert len(sample_pct) == 10
