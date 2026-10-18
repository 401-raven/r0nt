import json
import unicodedata
import pytest

from r0nt.chunker import ChunkInfo, FileResult, SkippedFile, hash_chunk
from r0nt.manifest import (
    FORMAT_VERSION,
    TOOL_VERSION,
    build_manifest,
    canonical_json,
    file_entry_leaf_data,
    manifest_from_bytes,
    manifest_hash,
    manifest_to_bytes,
)
from r0nt.signing import generate_keypair, verify_signature


def test_canonical_json_rules():
    obj = {
        "b": 2,
        "a": 1,
        "c": "café",
        "nested": {"z": 10, "y": 20},
    }
    encoded = canonical_json(obj)
    # Keys must be sorted, no extra whitespace
    assert encoded == b'{"a":1,"b":2,"c":"caf\xc3\xa9","nested":{"y":20,"z":10}}'

    # Unicode normalization: decomposed NFD 'e\u0301' should normalize to NFC '\xe9'
    nfd_str = "cafe\u0301"
    assert unicodedata.is_normalized("NFD", nfd_str)
    encoded_nfc = canonical_json({"text": nfd_str})
    decoded = json.loads(encoded_nfc.decode("utf-8"))
    assert unicodedata.is_normalized("NFC", decoded["text"])
    assert decoded["text"] == "café"


def test_file_entry_leaf_data():
    leaf_bytes = file_entry_leaf_data(path="docs/readme.txt", size=1024, file_root="00" * 32)
    # Sorted keys: file_root, path, size
    expected = b'{"file_root":"' + (b"00" * 32) + b'","path":"docs/readme.txt","size":1024}'
    assert leaf_bytes == expected


def test_build_manifest():
    priv, pub = generate_keypair()

    data1 = b"chunk1"
    h1 = hash_chunk(data1)
    file1 = FileResult(
        path="b.txt",
        size=len(data1),
        mtime=1700000000,
        chunks=[ChunkInfo(hash=h1, data=data1)],
        unstable=False,
    )

    data2 = b"chunk2"
    h2 = hash_chunk(data2)
    file2 = FileResult(
        path="a.txt",
        size=len(data2),
        mtime=1700000001,
        chunks=[ChunkInfo(hash=h2, data=data2)],
        unstable=True,
    )

    skipped = [
        SkippedFile(path="link.txt", reason="symlink", type="symlink", target="a.txt")
    ]

    manifest = build_manifest(
        file_results=[file1, file2],  # Passed out of order: b.txt then a.txt
        skipped_files=skipped,
        chunk_size=1048576,
        prev_manifest_hash="aa" * 32,
        sequence_number=2,
        private_key=priv,
        public_key=pub,
    )

    # Must be sorted by path in files list: a.txt then b.txt
    assert manifest["files"][0]["path"] == "a.txt"
    assert manifest["files"][0].get("unstable") is True
    assert manifest["files"][1]["path"] == "b.txt"
    assert "unstable" not in manifest["files"][1]

    assert manifest["sequence_number"] == 2
    assert manifest["prev_manifest_hash"] == "aa" * 32
    assert manifest["format_version"] == FORMAT_VERSION
    assert manifest["tool_version"] == TOOL_VERSION
    assert manifest["skipped_files"][0]["type"] == "symlink"

    # Verify manifest hash and signature
    m_hash = manifest_hash(manifest)
    sig_bytes = bytes.fromhex(manifest["signature"])
    assert verify_signature(pub, bytes.fromhex(m_hash), sig_bytes)


def test_manifest_roundtrip():
    priv, pub = generate_keypair()
    manifest = build_manifest(
        file_results=[],
        skipped_files=[],
        chunk_size=1048576,
        prev_manifest_hash=None,
        sequence_number=1,
        private_key=priv,
        public_key=pub,
    )

    raw_bytes = manifest_to_bytes(manifest)
    loaded = manifest_from_bytes(raw_bytes)
    assert loaded == manifest
    assert manifest_hash(loaded) == manifest_hash(manifest)
