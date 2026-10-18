"""Tests for snapshot list, show, and diff engine (SPEC_PHASE2 §3)."""

from __future__ import annotations

from pathlib import Path
import pytest

from r0nt.chunker import scan_source
from r0nt.diff import diff_snapshots, get_snapshot_detail, list_snapshots
from r0nt.manifest import build_manifest, manifest_hash
from r0nt.signing import generate_keypair
from r0nt.store import ChunkStore, ManifestStore, WitnessDB


def _make_snapshot(source_dir: Path, repo: Path, wdb: WitnessDB, priv, pub, seq: int, prev_hash: str | None):
    cs = ChunkStore(repo)
    ms = ManifestStore(repo)
    file_results, skipped = scan_source(source_dir)
    for fr in file_results:
        for c in fr.chunks:
            cs.write_chunk(c.hash, c.data)

    m = build_manifest(
        file_results=file_results,
        skipped_files=skipped,
        chunk_size=1024 * 1024,
        prev_manifest_hash=prev_hash,
        sequence_number=seq,
        private_key=priv,
        public_key=pub,
    )
    ms.write_manifest(m)
    wdb.record_manifest(m)
    return m


def test_list_and_show_snapshots(tmp_path: Path):
    source = tmp_path / "src"
    source.mkdir()
    (source / "a.txt").write_text("file a")
    (source / "b.txt").write_text("file b")

    repo = tmp_path / "repo"
    wdb = WitnessDB(tmp_path / "w.db", b"x" * 32)
    priv, pub = generate_keypair()

    m1 = _make_snapshot(source, repo, wdb, priv, pub, 1, None)

    summaries = list_snapshots(repo, pub)
    assert len(summaries) == 1
    assert summaries[0].sequence_number == 1
    assert summaries[0].backup_id == m1["backup_id"]
    assert summaries[0].file_count == 2
    assert summaries[0].signature_valid is True

    detail = get_snapshot_detail(repo, m1["backup_id"], pub)
    assert detail.summary.backup_id == m1["backup_id"]
    assert len(detail.files) == 2

    # Filtered show
    filtered_detail = get_snapshot_detail(repo, m1["backup_id"], pub, prefix="a.txt")
    assert len(filtered_detail.files) == 1
    assert filtered_detail.files[0]["path"] == "a.txt"
    wdb.close()


def test_diff_snapshots(tmp_path: Path):
    source = tmp_path / "src"
    source.mkdir()
    (source / "keep.txt").write_text("unchanged")
    (source / "modify.txt").write_text("version 1")
    (source / "remove.txt").write_text("to be deleted")

    repo = tmp_path / "repo"
    wdb = WitnessDB(tmp_path / "w.db", b"x" * 32)
    priv, pub = generate_keypair()

    m1 = _make_snapshot(source, repo, wdb, priv, pub, 1, None)
    m1_hash = manifest_hash(m1)

    # Modify folder for snapshot 2
    (source / "modify.txt").write_text("version 2 (modified)")
    (source / "remove.txt").unlink()
    (source / "added.txt").write_text("new file")

    m2 = _make_snapshot(source, repo, wdb, priv, pub, 2, m1_hash)

    diff = diff_snapshots(repo, m1["backup_id"], m2["backup_id"])
    assert diff.added_files == ["added.txt"]
    assert diff.removed_files == ["remove.txt"]
    assert diff.modified_files == ["modify.txt"]
    wdb.close()


def test_diff_identical_snapshots(tmp_path: Path):
    source = tmp_path / "src"
    source.mkdir()
    (source / "file.txt").write_text("same content")

    repo = tmp_path / "repo"
    wdb = WitnessDB(tmp_path / "w.db", b"x" * 32)
    priv, pub = generate_keypair()

    m1 = _make_snapshot(source, repo, wdb, priv, pub, 1, None)

    diff = diff_snapshots(repo, m1["backup_id"], m1["backup_id"])
    assert diff.added_files == []
    assert diff.removed_files == []
    assert diff.modified_files == []
    wdb.close()
