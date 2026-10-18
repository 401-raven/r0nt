"""Restore engine for r0nt (SPEC_PHASE2 §3).

Restores snapshots with pre-flight signature checks, chunk verification,
file Merkle root verification, atomic file replacement, and strict safety rails.
"""

from __future__ import annotations

import hashlib
import hmac as hmac_mod
import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from r0nt.manifest import manifest_hash
from r0nt.merkle import MerkleTree
from r0nt.signing import verify_signature
from r0nt.store import ChunkStore, WitnessDB


@dataclass
class RestoreResult:
    """Summary of a snapshot restore operation."""
    backup_id: str
    target_dir: str
    files_restored: int
    bytes_restored: int
    errors: list[str] = field(default_factory=list)


def _validate_path_traversal(rel_path: str, target_root: Path) -> Path:
    """Ensure rel_path is safe and resolves strictly inside target_root."""
    if not rel_path or rel_path.startswith('/') or rel_path.startswith('\\'):
        raise ValueError(f"Path traversal detected (absolute path): {rel_path}")

    # Check for '..' components
    parts = Path(rel_path).parts
    if '..' in parts:
        raise ValueError(f"Path traversal detected ('..' component): {rel_path}")

    resolved_target = target_root.resolve()
    dest = (resolved_target / rel_path).resolve()

    try:
        dest.relative_to(resolved_target)
    except ValueError as exc:
        raise ValueError(f"Path traversal detected: {rel_path}") from exc

    return dest


def restore_snapshot(
    manifest: dict,
    repo_path: Path,
    target_dir: Path,
    public_key: Ed25519PublicKey,
    witness_db: WitnessDB | None = None,
    paths: list[str] | None = None,
    allow_nonempty: bool = False,
    overwrite: bool = False,
    progress_callback: Any = None,
    cancel_event: Any = None,
) -> RestoreResult:
    """Restore all or selected files from a snapshot manifest.

    Args:
        manifest: Deserialized manifest dictionary.
        repo_path: Path to repository root.
        target_dir: Destination directory.
        public_key: Pinned Ed25519 public key.
        witness_db: Optional WitnessDB to cross-check chain and manifest hash.
        paths: Optional list of path prefixes to filter files to restore.
        allow_nonempty: If True, allow restoring into an existing non-empty directory.
        overwrite: If True, overwrite existing files in target.
        progress_callback: Optional callable(current_file, files_done, total_files, bytes_done, total_bytes).
        cancel_event: Optional threading.Event for cancellation.

    Returns:
        RestoreResult summary.
    """
    bid = manifest.get('backup_id', 'unknown')

    # ---- 1. Pre-flight verification ----
    # 1a. Verify Ed25519 signature
    m_hash = manifest_hash(manifest)
    sig_hex = manifest.get('signature', '')
    try:
        sig_bytes = bytes.fromhex(sig_hex)
    except ValueError:
        raise ValueError(f"Pre-restore check failed: malformed signature in manifest {bid}")

    if not verify_signature(public_key, bytes.fromhex(m_hash), sig_bytes):
        raise ValueError(f"Pre-restore check failed: manifest signature invalid for {bid}")

    # 1b. Verify witness DB cross-check if provided
    if witness_db is not None:
        records = witness_db.get_all_records()
        rec = next((r for r in records if r['backup_id'] == bid), None)
        if rec is not None:
            if not hmac_mod.compare_digest(m_hash, rec['manifest_hash']):
                raise ValueError(
                    f"Pre-restore check failed: manifest hash mismatch with witness DB for {bid}"
                )

    # ---- 2. Target directory safety checks ----
    target_dir = Path(target_dir).resolve()
    if target_dir.exists():
        # Check if non-empty
        try:
            has_entries = any(target_dir.iterdir())
        except OSError:
            has_entries = False

        if has_entries and not allow_nonempty:
            raise ValueError(
                f"Target directory '{target_dir}' is not empty. Use --allow-nonempty to restore into it."
            )
    else:
        target_dir.mkdir(parents=True, exist_ok=True)

    # ---- 3. Filter files ----
    all_files = manifest.get('files', [])
    to_restore: list[dict] = []
    if paths:
        norm_prefixes = [p.replace('\\', '/').rstrip('/') for p in paths]
        for f in all_files:
            fpath = f['path']
            if any(fpath == p or fpath.startswith(f"{p}/") for p in norm_prefixes):
                to_restore.append(f)
    else:
        to_restore = list(all_files)

    # Pre-validate all target paths before writing anything
    dest_map: dict[str, Path] = {}
    for f in to_restore:
        dest = _validate_path_traversal(f['path'], target_dir)
        if dest.exists() and not overwrite:
            raise ValueError(
                f"Destination file already exists: {dest}. Use --overwrite to allow replacing files."
            )
        dest_map[f['path']] = dest

    # ---- 4. Streaming restore ----
    chunk_store = ChunkStore(repo_path)
    total_bytes = sum(f['size'] for f in to_restore)
    bytes_restored = 0
    files_restored = 0

    for f in to_restore:
        if cancel_event and cancel_event.is_set():
            break

        fpath = f['path']
        dest_file = dest_map[fpath]
        dest_file.parent.mkdir(parents=True, exist_ok=True)

        tmp_path: Path | None = None
        try:
            # Write chunk payloads into a temporary file
            with tempfile.NamedTemporaryFile(
                dir=dest_file.parent, delete=False, mode='wb', suffix='.tmp'
            ) as tmp:
                tmp_path = Path(tmp.name)
                chunk_hashes = f.get('chunks', [])
                chunk_hash_bytes: list[bytes] = []

                for chash in chunk_hashes:
                    if cancel_event and cancel_event.is_set():
                        break
                    # read_chunk verifies SHA-256 against filename
                    chunk_data = chunk_store.read_chunk(chash)
                    tmp.write(chunk_data)
                    chunk_hash_bytes.append(bytes.fromhex(chash))

            if cancel_event and cancel_event.is_set():
                if tmp_path and tmp_path.exists():
                    tmp_path.unlink()
                break

            # Verify file Merkle root
            file_tree = MerkleTree(chunk_hash_bytes)
            expected_root = f.get('file_root', '')
            if not hmac_mod.compare_digest(file_tree.root_hex, expected_root):
                raise ValueError(
                    f"File Merkle root mismatch on restored file '{fpath}': "
                    f"recomputed={file_tree.root_hex}, manifest={expected_root}"
                )

            # Restore mtime
            mtime = f.get('mtime', 0)
            os.utime(str(tmp_path), (mtime, mtime))

            # Atomic rename
            tmp_path.rename(dest_file)
            tmp_path = None

            files_restored += 1
            bytes_restored += f['size']

            if progress_callback:
                progress_callback(
                    current_file=fpath,
                    files_done=files_restored,
                    total_files=len(to_restore),
                    bytes_done=bytes_restored,
                    total_bytes=total_bytes,
                )

        except Exception:
            # Clean up temporary file so partial or corrupt files are never left behind
            if tmp_path and tmp_path.exists():
                try:
                    tmp_path.unlink()
                except OSError:
                    pass
            raise

    return RestoreResult(
        backup_id=bid,
        target_dir=str(target_dir),
        files_restored=files_restored,
        bytes_restored=bytes_restored,
    )
