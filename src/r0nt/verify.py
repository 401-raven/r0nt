"""Verifier: recompute hashes and compare against signed manifests
and the witness DB.

Verification pipeline (SPEC §4 + §7 + §8, SPEC_PHASE2 §3):
  1. Verify witness DB row MACs.
  2. For each repo manifest: recompute hash, verify signature,
     cross-check against the witness DB.
  3. Verify stored chunks (existence in quick mode; content SHA-256 in full/sample modes).
  4. Rebuild per-file and backup-root Merkle trees.
  5. Validate the hash chain (delegated to ``chain.validate_chain``).
  6. Detect manifests in the repo but not in the witness DB.
"""

from __future__ import annotations

import hmac as hmac_mod
from pathlib import Path
from typing import Any, Literal

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from r0nt.chain import Finding, validate_chain
from r0nt.manifest import file_entry_leaf_data, manifest_hash
from r0nt.merkle import MerkleTree
from r0nt.signing import verify_signature
from r0nt.store import ChunkStore, ManifestStore, WitnessDB


def verify_with_stats(
    repo_path: Path,
    source_path: Path | None,
    public_key: Ed25519PublicKey,
    witness_db: WitnessDB,
    mode: Literal["quick", "full", "sample"] = "full",
    sample_percent: float = 10.0,
    progress_callback: Any = None,
    cancel_event: Any = None,
) -> tuple[list[Finding], dict[str, Any]]:
    """Run verification in the requested mode and return findings and statistics."""
    findings: list[Finding] = []
    chunk_store = ChunkStore(repo_path)
    manifest_store = ManifestStore(repo_path)

    repo_manifests = manifest_store.load_all_manifests()
    witness_records = witness_db.get_all_records()

    stats: dict[str, Any] = {
        "mode": mode,
        "total_chunks": 0,
        "checked_chunks": 0,
        "sampled_chunks": 0,
        "bytes_read": 0,
        "sample_percent": sample_percent if mode == "sample" else None,
        "snapshots_checked": len(repo_manifests),
    }

    # ---- 1. Witness DB row MAC verification ----
    for wr in witness_records:
        if cancel_event and cancel_event.is_set():
            break
        if not witness_db.verify_row_mac(wr):
            findings.append(Finding(
                type='manifest_modified',
                message=(
                    f"Witness DB row MAC invalid for backup {wr['backup_id']}. "
                    f"The witness database may have been tampered with."
                ),
                backup_id=wr['backup_id'],
            ))

    witness_by_id = {w['backup_id']: w for w in witness_records}

    # ---- 2. Per-manifest verification ----
    for manifest in repo_manifests:
        if cancel_event and cancel_event.is_set():
            break

        bid = manifest['backup_id']

        # 2a. Recompute manifest_hash
        m_hash = manifest_hash(manifest)

        # 2b. Verify Ed25519 signature
        sig_hex = manifest.get('signature', '')
        try:
            sig_bytes = bytes.fromhex(sig_hex)
        except ValueError:
            findings.append(Finding(
                type='signature_invalid',
                message=f"Malformed signature hex in manifest {bid}",
                backup_id=bid,
            ))
            continue

        if not verify_signature(public_key, bytes.fromhex(m_hash), sig_bytes):
            findings.append(Finding(
                type='signature_invalid',
                message=f"Ed25519 signature verification failed for manifest {bid}",
                backup_id=bid,
            ))

        # 2c. Cross-check manifest hash with witness DB
        if bid in witness_by_id:
            wr = witness_by_id[bid]
            if not hmac_mod.compare_digest(m_hash, wr['manifest_hash']):
                findings.append(Finding(
                    type='manifest_modified',
                    message=(
                        f"Manifest hash mismatch for {bid}: "
                        f"repo={m_hash}, witness={wr['manifest_hash']}"
                    ),
                    backup_id=bid,
                ))

        # ---- 3. Chunk verification ----
        for file_record in manifest.get('files', []):
            if cancel_event and cancel_event.is_set():
                break

            fpath = file_record['path']
            for idx, chash in enumerate(file_record.get('chunks', [])):
                stats["total_chunks"] += 1

                # Existence check
                if not chunk_store.has_chunk(chash):
                    findings.append(Finding(
                        type='chunk_missing',
                        message=f"Chunk {chash} missing for file {fpath}",
                        backup_id=bid,
                        file_path=fpath,
                        chunk_index=idx,
                        chunk_hash=chash,
                    ))
                    continue

                if mode == "quick":
                    # Quick mode: verify existence only, do NOT read chunk data
                    continue

                should_read = False
                if mode == "full":
                    should_read = True
                elif mode == "sample":
                    # Deterministic hash sampling
                    prefix_val = int(chash[:8], 16)
                    ratio = (prefix_val / 0xFFFFFFFF) * 100.0
                    if ratio <= sample_percent or stats["sampled_chunks"] == 0:
                        should_read = True
                        stats["sampled_chunks"] += 1

                if should_read:
                    stats["checked_chunks"] += 1
                    try:
                        data = chunk_store.read_chunk(chash)
                        stats["bytes_read"] += len(data)
                    except ValueError as exc:
                        findings.append(Finding(
                            type='chunk_modified',
                            message=str(exc),
                            backup_id=bid,
                            file_path=fpath,
                            chunk_index=idx,
                            chunk_hash=chash,
                        ))

        # ---- 4. Merkle tree verification ----
        # 4a. Per-file roots
        for file_record in manifest.get('files', []):
            fpath = file_record['path']
            chunk_hashes = file_record.get('chunks', [])
            expected_root = file_record.get('file_root', '')

            tree = MerkleTree([bytes.fromhex(h) for h in chunk_hashes])
            if not hmac_mod.compare_digest(tree.root_hex, expected_root):
                findings.append(Finding(
                    type='manifest_modified',
                    message=(
                        f"File Merkle root mismatch for {fpath}: "
                        f"recomputed={tree.root_hex}, manifest={expected_root}"
                    ),
                    backup_id=bid,
                    file_path=fpath,
                ))

        # 4b. Backup root
        sorted_files = sorted(
            manifest.get('files', []),
            key=lambda f: f['path'].encode('utf-8'),
        )
        file_leaves = [
            file_entry_leaf_data(fr['path'], fr['size'], fr['file_root'])
            for fr in sorted_files
        ]
        backup_tree = MerkleTree(file_leaves)
        expected_backup_root = manifest.get('root_hash', '')

        if not hmac_mod.compare_digest(backup_tree.root_hex, expected_backup_root):
            findings.append(Finding(
                type='manifest_modified',
                message=(
                    f"Backup root hash mismatch for {bid}: "
                    f"recomputed={backup_tree.root_hex}, "
                    f"manifest={expected_backup_root}"
                ),
                backup_id=bid,
            ))

        if progress_callback:
            progress_callback(
                current_snapshot=bid,
                snapshots_done=repo_manifests.index(manifest) + 1,
                total_snapshots=len(repo_manifests),
            )

    # ---- 5. Hash-chain validation ----
    chain_findings = validate_chain(repo_manifests, witness_records)
    findings.extend(chain_findings)

    # ---- 6. Manifests in repo but not in witness DB ----
    witness_ids = {w['backup_id'] for w in witness_records}
    for manifest in repo_manifests:
        if manifest['backup_id'] not in witness_ids:
            findings.append(Finding(
                type='file_added',
                message=(
                    f"Manifest {manifest['backup_id']} (seq {manifest.get('sequence_number')}) "
                    f"exists in repo but not in the witness DB (possible crash between "
                    f"manifest write and witness recording, or unauthorized manifest insertion)"
                ),
                backup_id=manifest['backup_id'],
            ))

    return findings, stats


def verify_all(
    repo_path: Path,
    source_path: Path | None,
    public_key: Ed25519PublicKey,
    witness_db: WitnessDB,
    mode: Literal["quick", "full", "sample"] = "full",
    sample_percent: float = 10.0,
    progress_callback: Any = None,
    cancel_event: Any = None,
) -> list[Finding]:
    """Run the verification pipeline and return findings."""
    findings, _stats = verify_with_stats(
        repo_path=repo_path,
        source_path=source_path,
        public_key=public_key,
        witness_db=witness_db,
        mode=mode,
        sample_percent=sample_percent,
        progress_callback=progress_callback,
        cancel_event=cancel_event,
    )
    return findings
