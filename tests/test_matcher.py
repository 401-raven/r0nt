"""Tests for gitignore-style path matcher (SPEC_PHASE2 §2)."""

from __future__ import annotations

import pytest
from r0nt.matcher import PathMatcher


def test_matcher_extension():
    matcher = PathMatcher(["*.tmp", "*.bak"])
    assert matcher.matches("test.tmp")
    assert matcher.matches("sub/dir/test.tmp")
    assert matcher.matches("file.bak")
    assert not matcher.matches("test.txt")
    assert not matcher.matches("tmp/file.txt")


def test_matcher_directory_glob():
    matcher = PathMatcher(["node_modules/**", ".cache/**"])
    assert matcher.matches("node_modules/package.json")
    assert matcher.matches("node_modules/deep/nested/file.js")
    assert matcher.matches(".cache/data.bin")
    assert not matcher.matches("src/node_modules_helper.js")


def test_matcher_exact_filename():
    matcher = PathMatcher(["pagefile.sys", "thumbs.db"])
    assert matcher.matches("pagefile.sys")
    assert matcher.matches("C/pagefile.sys")
    assert matcher.matches("sub/thumbs.db")
    assert not matcher.matches("pagefile.sys.bak")


def test_matcher_empty_patterns():
    matcher = PathMatcher([])
    assert not matcher.matches("any/file.txt")


def test_matcher_windows_recycle_bin():
    matcher = PathMatcher(["$RECYCLE.BIN/**", "System Volume Information/**"])
    assert matcher.matches("$RECYCLE.BIN/deleted.txt")
    assert matcher.matches("System Volume Information/store.dat")
    assert not matcher.matches("MyDocs/info.txt")
