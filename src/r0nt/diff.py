"""Snapshot inspection and diff engine (SPEC_PHASE2 §3).

Provides listing, detailed inspection, and comparison of snapshots.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from r0nt.manifest import manifest_hash
from r0nt.signing import verify_signature
from r0nt.store import ManifestStore


@dataclass
class SnapshotSummary:
    """High-level summary of a snapshot."""
    sequence_number: int
    backup_id: str
    created_at: str
    file_count: int
    total_size: int
    signature_valid: bool
    root_hash: str


@dataclass
class SnapshotDetail:
    """Detailed view of a snapshot."""
    summary: SnapshotSummary
    chunk_size: int
    key_id: str
    prev_manifest_hash: str | None
    files: list[dict]
    skipped_files: list[dict] = field(default_factory=list)


@dataclass
class DiffResult:
    """Differences between two snapshots."""
    snapshot_a: str
    snapshot_b: str
    added_files: list[str]
    removed_files: list[str]
    modified_files: list[str]


def _find_manifest(manifest_store: ManifestStore, identifier: str | int) -> dict:
    """Find a manifest by backup_id or sequence_number."""
    all_manifests = manifest_store.load_all_manifests()
    ident_str = str(identifier).strip()

    # Try matching backup_id
    for m in all_manifests:
        if m.get("backup_id") == ident_str or m.get("backup_id", "").startswith(ident_str):
            return m

    # Try matching sequence_number
    try:
        seq = int(ident_str)
        for m in all_manifests:
            if m.get("sequence_number") == seq:
                return m
    except ValueError:
        pass

    raise FileNotFoundError(f"Snapshot '{identifier}' not found in repository.")


def list_snapshots(repo_path: Path, public_key: Ed25519PublicKey) -> list[SnapshotSummary]:
    """List all snapshots in repo_path, ordered by sequence_number."""
    manifest_store = ManifestStore(repo_path)
    manifests = manifest_store.load_all_manifests()
    summaries: list[SnapshotSummary] = []

    for m in sorted(manifests, key=lambda x: x.get("sequence_number", 0)):
        bid = m.get("backup_id", "")
        seq = m.get("sequence_number", 0)
        created_at = m.get("created_at", "")
        files = m.get("files", [])
        total_size = sum(f.get("size", 0) for f in files)
        root_hash = m.get("root_hash", "")

        # Verify signature
        m_hash = manifest_hash(m)
        sig_hex = m.get("signature", "")
        is_valid = False
        try:
            sig_bytes = bytes.fromhex(sig_hex)
            is_valid = verify_signature(public_key, bytes.fromhex(m_hash), sig_bytes)
        except Exception:
            is_valid = False

        summaries.append(SnapshotSummary(
            sequence_number=seq,
            backup_id=bid,
            created_at=created_at,
            file_count=len(files),
            total_size=total_size,
            signature_valid=is_valid,
            root_hash=root_hash,
        ))

    return summaries


def get_snapshot_detail(
    repo_path: Path,
    identifier: str | int,
    public_key: Ed25519PublicKey,
    prefix: str | None = None,
) -> SnapshotDetail:
    """Retrieve full details for a snapshot, with optional path prefix filtering."""
    manifest_store = ManifestStore(repo_path)
    m = _find_manifest(manifest_store, identifier)

    summaries = list_snapshots(repo_path, public_key)
    summary = next((s for s in summaries if s.backup_id == m["backup_id"]), None)
    if summary is None:
        m_hash = manifest_hash(m)
        is_valid = False
        try:
            is_valid = verify_signature(public_key, bytes.fromhex(m_hash), bytes.fromhex(m.get("signature", "")))
        except Exception:
            is_valid = False
        summary = SnapshotSummary(
            sequence_number=m.get("sequence_number", 0),
            backup_id=m.get("backup_id", ""),
            created_at=m.get("created_at", ""),
            file_count=len(m.get("files", [])),
            total_size=sum(f.get("size", 0) for f in m.get("files", [])),
            signature_valid=is_valid,
            root_hash=m.get("root_hash", ""),
        )

    all_files = m.get("files", [])
    if prefix:
        norm_prefix = prefix.replace('\\', '/').rstrip('/')
        files = [
            f for f in all_files
            if f["path"] == norm_prefix or f["path"].startswith(f"{norm_prefix}/")
        ]
    else:
        files = list(all_files)

    return SnapshotDetail(
        summary=summary,
        chunk_size=m.get("chunk_size", 0),
        key_id=m.get("key_id", ""),
        prev_manifest_hash=m.get("prev_manifest_hash"),
        files=files,
        skipped_files=m.get("skipped_files", []),
    )


def diff_snapshots(
    repo_path: Path,
    ident_a: str | int,
    ident_b: str | int,
) -> DiffResult:
    """Compute the difference between two snapshots (ident_a -> ident_b)."""
    manifest_store = ManifestStore(repo_path)
    m_a = _find_manifest(manifest_store, ident_a)
    m_b = _find_manifest(manifest_store, ident_b)

    files_a = {f["path"]: f for f in m_a.get("files", [])}
    files_b = {f["path"]: f for f in m_b.get("files", [])}

    added = sorted([p for p in files_b if p not in files_a])
    removed = sorted([p for p in files_a if p not in files_b])
    modified: list[str] = []

    for p in files_a:
        if p in files_b:
            fa = files_a[p]
            fb = files_b[p]
            if fa.get("size") != fb.get("size") or fa.get("file_root") != fb.get("file_root"):
                modified.append(p)

    return DiffResult(
        snapshot_a=m_a["backup_id"],
        snapshot_b=m_b["backup_id"],
        added_files=added,
        removed_files=removed,
        modified_files=sorted(modified),
    )
