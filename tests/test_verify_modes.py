"""Tests for extended verify modes: quick, full, sample (SPEC_PHASE2 §3)."""

from __future__ import annotations

from pathlib import Path
import pytest

from r0nt.chunker import scan_source
from r0nt.manifest import build_manifest
from r0nt.signing import generate_keypair
from r0nt.store import ChunkStore, ManifestStore, WitnessDB
from r0nt.verify import verify_all, verify_with_stats


def _setup_repo(tmp_path: Path):
    source = tmp_path / "src"
    source.mkdir()
    (source / "doc1.txt").write_text("Document 1 content")
    (source / "doc2.txt").write_text("Document 2 content")
    (source / "doc3.txt").write_text("Document 3 content")

    repo = tmp_path / "repo"
    wdb_path = tmp_path / "witness.db"
    priv, pub = generate_keypair()
    wdb = WitnessDB(wdb_path, b"w" * 32)

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

    return repo, wdb, pub, priv, manifest


def test_verify_quick_clean(tmp_path: Path):
    repo, wdb, pub, priv, manifest = _setup_repo(tmp_path)

    findings, stats = verify_with_stats(
        repo_path=repo,
        source_path=None,
        public_key=pub,
        witness_db=wdb,
        mode="quick",
    )

    assert findings == []
    assert stats["mode"] == "quick"
    assert stats["total_chunks"] == 3
    assert stats["bytes_read"] == 0  # quick does not read chunk contents
    wdb.close()


def test_verify_quick_detects_missing_chunk(tmp_path: Path):
    repo, wdb, pub, priv, manifest = _setup_repo(tmp_path)

    # Delete one chunk
    chash = manifest["files"][0]["chunks"][0]
    cfile = repo / "chunks" / chash[:2] / chash
    cfile.unlink()

    findings = verify_all(
        repo_path=repo,
        source_path=None,
        public_key=pub,
        witness_db=wdb,
        mode="quick",
    )

    assert len(findings) == 1
    assert findings[0].type == "chunk_missing"
    wdb.close()


def test_verify_quick_ignores_byte_flip_as_documented(tmp_path: Path):
    repo, wdb, pub, priv, manifest = _setup_repo(tmp_path)

    # Flip one byte in stored chunk
    chash = manifest["files"][0]["chunks"][0]
    cfile = repo / "chunks" / chash[:2] / chash
    data = bytearray(cfile.read_bytes())
    data[0] ^= 0xFF
    cfile.write_bytes(bytes(data))

    # Quick mode only checks existence, so byte flip is NOT caught
    findings_quick = verify_all(
        repo_path=repo,
        source_path=None,
        public_key=pub,
        witness_db=wdb,
        mode="quick",
    )
    assert findings_quick == []

    # Full mode DOES catch byte flip
    findings_full = verify_all(
        repo_path=repo,
        source_path=None,
        public_key=pub,
        witness_db=wdb,
        mode="full",
    )
    assert len(findings_full) > 0
    assert any(f.type == "chunk_modified" for f in findings_full)
    wdb.close()


def test_verify_sample_mode(tmp_path: Path):
    repo, wdb, pub, priv, manifest = _setup_repo(tmp_path)

    findings, stats = verify_with_stats(
        repo_path=repo,
        source_path=None,
        public_key=pub,
        witness_db=wdb,
        mode="sample",
        sample_percent=50.0,
    )

    assert findings == []
    assert stats["mode"] == "sample"
    assert stats["total_chunks"] == 3
    assert stats["sampled_chunks"] >= 1
    wdb.close()
