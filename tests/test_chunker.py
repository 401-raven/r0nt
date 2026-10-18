import os
from pathlib import Path
from unittest.mock import patch
import pytest

from r0nt.chunker import (
    canonicalize_path,
    chunk_file,
    hash_chunk,
    scan_source,
    FileResult,
    SkippedFile,
)


def test_hash_chunk():
    data = b"hello world"
    expected = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
    assert hash_chunk(data) == expected


def test_canonicalize_path(tmp_path: Path):
    source = tmp_path / "source"
    source.mkdir()

    file1 = source / "dir" / "file.txt"
    file1.parent.mkdir()
    file1.write_text("test")

    canonical = canonicalize_path(file1, source)
    assert canonical == "dir/file.txt"
    assert "/" in canonical
    assert "\\" not in canonical

    # Path traversal rejected
    with pytest.raises(ValueError, match="Path traversal"):
        # Craft a path outside source
        outside = tmp_path / "outside.txt"
        outside.write_text("outside")
        canonicalize_path(outside, source)


def test_chunk_file_empty(tmp_path: Path):
    source = tmp_path / "source"
    source.mkdir()
    empty = source / "empty.txt"
    empty.write_bytes(b"")

    res = chunk_file(empty, source, chunk_size=1024)
    assert res.path == "empty.txt"
    assert res.size == 0
    assert len(res.chunks) == 0
    assert not res.unstable


def test_chunk_file_multi_chunk(tmp_path: Path):
    source = tmp_path / "source"
    source.mkdir()
    f = source / "data.bin"
    chunk_size = 100
    content = b"A" * 250  # 3 chunks: 100, 100, 50
    f.write_bytes(content)

    res = chunk_file(f, source, chunk_size=chunk_size)
    assert res.path == "data.bin"
    assert res.size == 250
    assert len(res.chunks) == 3
    assert not res.unstable

    assert len(res.chunks[0].data) == 100
    assert len(res.chunks[1].data) == 100
    assert len(res.chunks[2].data) == 50

    reconstructed = b"".join(c.data for c in res.chunks)
    assert reconstructed == content
    assert res.chunks[0].hash == hash_chunk(b"A" * 100)
    assert res.chunks[2].hash == hash_chunk(b"A" * 50)


def test_chunk_file_toctou(tmp_path: Path):
    source = tmp_path / "source"
    source.mkdir()
    f = source / "changing.bin"
    f.write_bytes(b"initial")

    # Simulate TOCTOU by making _stat_file return different mtimes
    with patch("r0nt.chunker._stat_file", side_effect=[
        (7, 1000), (7, 1001),  # attempt 0
        (7, 1001), (7, 1002),  # attempt 1
        (7, 1002), (7, 1003),  # attempt 2
    ]):
        res = chunk_file(f, source, chunk_size=1024)
        assert res.unstable is True


def test_scan_source_basic(tmp_path: Path):
    source = tmp_path / "source"
    source.mkdir()

    (source / "a.txt").write_text("aaa")
    sub = source / "sub"
    sub.mkdir()
    (sub / "b.txt").write_text("bbb")

    results, skipped = scan_source(source)
    paths = {r.path for r in results}
    assert paths == {"a.txt", "sub/b.txt"}
    assert len(skipped) == 0


def test_scan_source_guard_limits(tmp_path: Path):
    source = tmp_path / "source"
    source.mkdir()

    (source / "large.bin").write_bytes(b"x" * 1000)

    # max_file_size exceeded: file is skipped
    results, skipped = scan_source(source, max_file_size=500)
    assert len(results) == 0
    assert len(skipped) == 1
    assert skipped[0].type == "too_large"

    # max_total_size exceeded: backup aborts
    (source / "small.bin").write_bytes(b"x" * 100)
    with pytest.raises(ValueError, match="Total backup size exceeds limit"):
        scan_source(source, max_total_size=50)

    # max_file_count exceeded: backup aborts
    with pytest.raises(ValueError, match="File count exceeds limit"):
        scan_source(source, max_file_count=1)


def test_scan_source_case_collision(tmp_path: Path):
    source = tmp_path / "source"
    source.mkdir()

    # Create seen_lower simulated collision
    with patch("os.walk", return_value=[(str(source), [], ["File.txt", "file.txt"])]):
        with pytest.raises(ValueError, match="Case collision"):
            scan_source(source)
