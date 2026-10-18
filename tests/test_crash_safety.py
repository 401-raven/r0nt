"""Tests for backup write order and crash interruption safety (SPEC_PHASE2 §5 & PHASE2_PLAN.md)."""

from __future__ import annotations

import tempfile
from pathlib import Path
import pytest

from r0nt.chunker import scan_source
from r0nt.manifest import build_manifest, manifest_to_bytes
from r0nt.signing import generate_keypair
from r0nt.store import ChunkStore, ManifestStore, WitnessDB
from r0nt.verify import verify_all


def _setup_base_env(tmp_path: Path):
    source = tmp_path / "src"
    source.mkdir()
    (source / "file.txt").write_text("crash test data")

    repo = tmp_path / "repo"
    wdb_file = tmp_path / "witness.db"
    priv, pub = generate_keypair()
    wdb = WitnessDB(wdb_file, b"k" * 32)
    return source, repo, wdb, priv, pub


def test_interruption_point_a_during_chunk_writes(tmp_path: Path):
    """Crash while writing chunks: chunks exist, no manifest exists -> Verifier: CLEAN."""
    source, repo, wdb, priv, pub = _setup_base_env(tmp_path)
    file_results, skipped = scan_source(source)
    cs = ChunkStore(repo)

    # Write chunk data but die before writing manifest
    for fr in file_results:
        for c in fr.chunks:
            cs.write_chunk(c.hash, c.data)

    findings = verify_all(repo, None, pub, wdb)
    assert findings == []
    wdb.close()


def test_interruption_point_b_before_manifest_rename(tmp_path: Path):
    """Crash after chunks written, temporary manifest exists (.tmp), not renamed -> Verifier: CLEAN."""
    source, repo, wdb, priv, pub = _setup_base_env(tmp_path)
    file_results, skipped = scan_source(source)
    cs = ChunkStore(repo)
    for fr in file_results:
        for c in fr.chunks:
            cs.write_chunk(c.hash, c.data)

    manifest = build_manifest(file_results, skipped, 1024 * 1024, None, 1, priv, pub)

    # Write .tmp manifest file without renaming to .json
    m_dir = repo / "manifests"
    m_dir.mkdir(parents=True, exist_ok=True)
    tmp_m = m_dir / f"{manifest['backup_id']}.tmp"
    tmp_m.write_bytes(manifest_to_bytes(manifest))

    findings = verify_all(repo, None, pub, wdb)
    assert findings == []
    wdb.close()


def test_interruption_point_c_manifest_written_witness_missing(tmp_path: Path):
    """Crash after manifest renamed to .json, but before witness record inserted -> Verifier: file_added."""
    source, repo, wdb, priv, pub = _setup_base_env(tmp_path)
    file_results, skipped = scan_source(source)
    cs = ChunkStore(repo)
    ms = ManifestStore(repo)

    for fr in file_results:
        for c in fr.chunks:
            cs.write_chunk(c.hash, c.data)

    manifest = build_manifest(file_results, skipped, 1024 * 1024, None, 1, priv, pub)
    ms.write_manifest(manifest)
    # Process dies here: witness_db.record_manifest() is NOT called!

    findings = verify_all(repo, None, pub, wdb)
    assert len(findings) == 1
    assert findings[0].type == "file_added"
    assert "not in the witness DB" in findings[0].message
    wdb.close()


def test_interruption_point_e_completed_backup(tmp_path: Path):
    """Full write order completed -> Verifier: CLEAN."""
    source, repo, wdb, priv, pub = _setup_base_env(tmp_path)
    file_results, skipped = scan_source(source)
    cs = ChunkStore(repo)
    ms = ManifestStore(repo)

    for fr in file_results:
        for c in fr.chunks:
            cs.write_chunk(c.hash, c.data)

    manifest = build_manifest(file_results, skipped, 1024 * 1024, None, 1, priv, pub)
    ms.write_manifest(manifest)
    wdb.record_manifest(manifest)

    findings = verify_all(repo, None, pub, wdb)
    assert findings == []
    wdb.close()
