"""Manifest building, canonical JSON serialization, and hashing.

Canonical JSON rules (SPEC §3):
  - ``json.dumps(obj, sort_keys=True, separators=(',',':'),
      ensure_ascii=False).encode('utf-8')``
  - Integers are bare; no floats, NaN, or Infinity.
  - All hex values are lowercase.
  - Unicode is NFC-normalized before serialization.
"""

from __future__ import annotations

import hashlib
import json
import unicodedata
import uuid
from datetime import datetime, timezone
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from r0nt.chunker import FileResult, SkippedFile
from r0nt.merkle import MerkleTree
from r0nt.signing import compute_key_id, sign

TOOL_VERSION = "0.1.0"
FORMAT_VERSION = 1


# ---------------------------------------------------------------------------
# Canonical JSON  (SPEC §3)
# ---------------------------------------------------------------------------

def canonical_json(obj: Any) -> bytes:
    """Serialize *obj* to canonical JSON bytes (UTF-8).

    Keys are sorted, no extra whitespace, ``ensure_ascii=False``.
    Strings are NFC-normalized before encoding.
    """
    normalized = _nfc_deep(obj)
    return json.dumps(
        normalized,
        sort_keys=True,
        separators=(',', ':'),
        ensure_ascii=False,
    ).encode('utf-8')


def _nfc_deep(obj: Any) -> Any:
    """Recursively NFC-normalize all strings in *obj*."""
    if isinstance(obj, str):
        return unicodedata.normalize('NFC', obj)
    if isinstance(obj, dict):
        return {_nfc_deep(k): _nfc_deep(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_nfc_deep(v) for v in obj]
    return obj


# ---------------------------------------------------------------------------
# File-entry leaf data  (SPEC §2)
# ---------------------------------------------------------------------------

def file_entry_leaf_data(path: str, size: int, file_root: str) -> bytes:
    """Encode a file entry as Merkle leaf data.

    Returns the canonical JSON bytes of::

        {"file_root":"<hex>","path":"<canonical>","size":<int>}
    """
    return canonical_json({
        "file_root": file_root,
        "path": path,
        "size": size,
    })


# ---------------------------------------------------------------------------
# Manifest construction
# ---------------------------------------------------------------------------

def build_manifest(
    file_results: list[FileResult],
    skipped_files: list[SkippedFile],
    chunk_size: int,
    prev_manifest_hash: str | None,
    sequence_number: int,
    private_key: Ed25519PrivateKey,
    public_key: Ed25519PublicKey,
) -> dict:
    """Build a complete, signed manifest dictionary.

    Steps:
      1. Build per-file Merkle trees → ``file_root`` per file.
      2. Build the backup-root tree over file entries sorted by path.
      3. Assemble the manifest dict (without signature).
      4. Compute ``manifest_hash`` and sign it.
      5. Attach the hex signature.
    """
    backup_id = str(uuid.uuid4())
    created_at = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    key_id = compute_key_id(public_key)

    # Sort file results by canonical path (UTF-8 byte order)
    sorted_results = sorted(file_results, key=lambda r: r.path.encode('utf-8'))

    files_list: list[dict] = []
    file_leaves: list[bytes] = []

    for fr in sorted_results:
        # Per-file Merkle tree over raw 32-byte chunk hashes
        chunk_hash_bytes = [bytes.fromhex(c.hash) for c in fr.chunks]
        file_tree = MerkleTree(chunk_hash_bytes)
        file_root_hex = file_tree.root_hex

        file_record: dict = {
            "chunks": [c.hash for c in fr.chunks],
            "file_root": file_root_hex,
            "mtime": fr.mtime,
            "path": fr.path,
            "size": fr.size,
        }
        if fr.unstable:
            file_record["unstable"] = True
        files_list.append(file_record)

        # Leaf data for the backup-root tree
        file_leaves.append(
            file_entry_leaf_data(fr.path, fr.size, file_root_hex)
        )

    # Backup-root Merkle tree
    backup_tree = MerkleTree(file_leaves)
    root_hash = backup_tree.root_hex

    # Skipped files (informational, included but not in the tree)
    skipped_records: list[dict] = []
    for sf in skipped_files:
        rec: dict = {"path": sf.path, "reason": sf.reason, "type": sf.type}
        if sf.target is not None:
            rec["target"] = sf.target
        skipped_records.append(rec)

    # Assemble manifest (no signature yet)
    manifest: dict = {
        "backup_id": backup_id,
        "chunk_size": chunk_size,
        "created_at": created_at,
        "files": files_list,
        "format_version": FORMAT_VERSION,
        "key_id": key_id,
        "prev_manifest_hash": prev_manifest_hash,
        "root_hash": root_hash,
        "sequence_number": sequence_number,
        "tool_version": TOOL_VERSION,
    }
    if skipped_records:
        manifest["skipped_files"] = skipped_records

    # Hash → sign → attach
    m_hash = manifest_hash(manifest)
    sig = sign(private_key, bytes.fromhex(m_hash))
    manifest["signature"] = sig.hex()

    return manifest


# ---------------------------------------------------------------------------
# Manifest hashing
# ---------------------------------------------------------------------------

def manifest_hash(manifest: dict) -> str:
    """SHA-256 of the canonical JSON bytes *without* ``signature``.

    Returns lowercase hex.
    """
    copy = {k: v for k, v in manifest.items() if k != 'signature'}
    return hashlib.sha256(canonical_json(copy)).hexdigest()


# ---------------------------------------------------------------------------
# Serialization helpers
# ---------------------------------------------------------------------------

def manifest_to_bytes(manifest: dict) -> bytes:
    """Serialize a manifest (including signature) to canonical JSON bytes."""
    return canonical_json(manifest)


def manifest_from_bytes(data: bytes) -> dict:
    """Deserialize manifest JSON bytes to a dict."""
    return json.loads(data)
