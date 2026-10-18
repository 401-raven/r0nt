"""Tests for multi-source directory scanning and exclude integration (SPEC_PHASE2 §2)."""

from __future__ import annotations

from pathlib import Path
import pytest

from r0nt.chunker import scan_sources
from r0nt.matcher import PathMatcher


def test_multi_source_scanning_with_labels(tmp_path: Path):
    doc_dir = tmp_path / "docs"
    doc_dir.mkdir()
    (doc_dir / "report.txt").write_text("hello report")

    photo_dir = tmp_path / "photos"
    photo_dir.mkdir()
    (photo_dir / "pic.png").write_bytes(b"fakepngbytes")

    sources = [
        ("Docs", doc_dir),
        ("Photos", photo_dir),
    ]

    results, skipped = scan_sources(sources)

    paths = [r.path for r in results]
    assert "Docs/report.txt" in paths
    assert "Photos/pic.png" in paths
    assert len(results) == 2
    assert len(skipped) == 0


def test_multi_source_excludes(tmp_path: Path):
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    (src_dir / "index.js").write_text("console.log('hi');")
    (src_dir / "index.tmp").write_text("temporary")
    nm = src_dir / "node_modules"
    nm.mkdir()
    (nm / "dep.js").write_text("module.exports = {};")

    matcher = PathMatcher(["*.tmp", "**/node_modules/**"])
    results, skipped = scan_sources([("Code", src_dir)], exclude_matcher=matcher)

    paths = [r.path for r in results]
    assert "Code/index.js" in paths
    assert "Code/index.tmp" not in paths
    assert "Code/node_modules/dep.js" not in paths
    # Excluded files must NEVER appear in skipped files either
    skipped_paths = [s.path for s in skipped]
    assert not any("tmp" in p for p in skipped_paths)
    assert not any("node_modules" in p for p in skipped_paths)


def test_single_source_unlabeled(tmp_path: Path):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    (data_dir / "file1.txt").write_text("content 1")

    # If label is None or empty, canonical path does not have label prefix
    results, skipped = scan_sources([("", data_dir)])
    paths = [r.path for r in results]
    assert paths == ["file1.txt"]


def test_duplicate_source_labels_rejected(tmp_path: Path):
    d1 = tmp_path / "d1"
    d2 = tmp_path / "d2"
    d1.mkdir()
    d2.mkdir()

    with pytest.raises(ValueError, match="Duplicate source label"):
        scan_sources([("docs", d1), ("docs", d2)])
