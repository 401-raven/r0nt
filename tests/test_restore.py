"""Tests for snapshot restore engine (SPEC_PHASE2 §3 & §7)."""

from __future__ import annotations

import os
from pathlib import Path
import pytest

from r0nt.chunker import scan_source
from r0nt.manifest import build_manifest, manifest_hash
from r0nt.restore import restore_snapshot
from r0nt.signing import generate_keypair
from r0nt.store import ChunkStore, ManifestStore, WitnessDB


def _create_test_backup(tmp_path: Path):
    source = tmp_path / "src"
    source.mkdir()
    (source / "file1.txt").write_text("Hello r0nt restore!")
    sub = source / "subdir"
    sub.mkdir()
    (sub / "file2.bin").write_bytes(b"binary-content-12345")

    repo = tmp_path / "repo"
    wdb_path = tmp_path / "witness.db"
    priv, pub = generate_keypair()
    wdb = WitnessDB(wdb_path, b"x" * 32)

    file_results, skipped = scan_source(source)
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

    return source, repo, wdb, priv, pub, manifest


def test_restore_round_trip(tmp_path: Path):
    source, repo, wdb, priv, pub, manifest = _create_test_backup(tmp_path)
    target = tmp_path / "restored"

    result = restore_snapshot(
        manifest=manifest,
        repo_path=repo,
        target_dir=target,
        public_key=pub,
        witness_db=wdb,
    )

    assert result.files_restored == 2
    assert (target / "file1.txt").read_text() == "Hello r0nt restore!"
    assert (target / "subdir" / "file2.bin").read_bytes() == b"binary-content-12345"

    # Verify mtime is preserved
    orig_mtime = int((source / "file1.txt").stat().st_mtime)
    rest_mtime = int((target / "file1.txt").stat().st_mtime)
    assert orig_mtime == rest_mtime
    wdb.close()


def test_restore_prefix_filtering(tmp_path: Path):
    source, repo, wdb, priv, pub, manifest = _create_test_backup(tmp_path)
    target = tmp_path / "restored_sub"

    result = restore_snapshot(
        manifest=manifest,
        repo_path=repo,
        target_dir=target,
        public_key=pub,
        witness_db=wdb,
        paths=["subdir"],
    )

    assert result.files_restored == 1
    assert (target / "subdir" / "file2.bin").exists()
    assert not (target / "file1.txt").exists()
    wdb.close()


def test_restore_refuses_nonempty_without_flag(tmp_path: Path):
    source, repo, wdb, priv, pub, manifest = _create_test_backup(tmp_path)
    target = tmp_path / "nonempty"
    target.mkdir()
    (target / "existing.txt").write_text("already here")

    with pytest.raises(ValueError, match="not empty"):
        restore_snapshot(
            manifest=manifest,
            repo_path=repo,
            target_dir=target,
            public_key=pub,
            witness_db=wdb,
            allow_nonempty=False,
        )
    wdb.close()


def test_restore_refuses_overwrite_without_flag(tmp_path: Path):
    source, repo, wdb, priv, pub, manifest = _create_test_backup(tmp_path)
    target = tmp_path / "overwrite_target"
    target.mkdir()
    (target / "file1.txt").write_text("old file")

    with pytest.raises(ValueError, match="already exists"):
        restore_snapshot(
            manifest=manifest,
            repo_path=repo,
            target_dir=target,
            public_key=pub,
            witness_db=wdb,
            allow_nonempty=True,
            overwrite=False,
        )
    wdb.close()


def test_restore_rejects_invalid_signature(tmp_path: Path):
    source, repo, wdb, priv, pub, manifest = _create_test_backup(tmp_path)
    target = tmp_path / "bad_sig_target"

    # Tamper with manifest signature
    bad_manifest = dict(manifest)
    bad_manifest["signature"] = "00" * 64

    with pytest.raises(ValueError, match="signature invalid"):
        restore_snapshot(
            manifest=bad_manifest,
            repo_path=repo,
            target_dir=target,
            public_key=pub,
            witness_db=wdb,
        )
    wdb.close()


def test_restore_detects_corrupt_chunk_and_cleans_up(tmp_path: Path):
    source, repo, wdb, priv, pub, manifest = _create_test_backup(tmp_path)
    target = tmp_path / "corrupt_chunk_target"

    # Corrupt chunk on disk
    chunk_hash = manifest["files"][0]["chunks"][0]
    chunk_file = repo / "chunks" / chunk_hash[:2] / chunk_hash
    chunk_file.write_bytes(b"corrupted-bytes-flushed")

    with pytest.raises(ValueError, match="Chunk integrity failure"):
        restore_snapshot(
            manifest=manifest,
            repo_path=repo,
            target_dir=target,
            public_key=pub,
            witness_db=wdb,
        )

    # Ensure no partial/corrupt files were left behind in target
    assert not (target / manifest["files"][0]["path"]).exists()
    wdb.close()


def test_restore_rejects_path_traversal(tmp_path: Path):
    source, repo, wdb, priv, pub, manifest = _create_test_backup(tmp_path)
    target = tmp_path / "traversal_target"

    # Inject path traversal into manifest files and re-sign
    bad_manifest = dict(manifest)
    bad_manifest["files"] = [
        {"path": "../escape.txt", "size": 10, "mtime": 100, "file_root": "0" * 64, "chunks": []}
    ]
    from r0nt.signing import sign
    m_hash = manifest_hash(bad_manifest)
    bad_manifest["signature"] = sign(priv, bytes.fromhex(m_hash)).hex()

    with pytest.raises(ValueError, match="Path traversal detected"):
        restore_snapshot(
            manifest=bad_manifest,
            repo_path=repo,
            target_dir=target,
            public_key=pub,
            witness_db=None,
        )
    wdb.close()
