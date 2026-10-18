"""Hash-chain linking and validation (SPEC §4).

Validates the chain formed by ``prev_manifest_hash`` links and
cross-checks against the witness DB to detect rollback, truncation,
and reordering.
"""

from __future__ import annotations

import hmac as hmac_mod
from typing import NamedTuple


class Finding(NamedTuple):
    """A single verification finding."""
    type: str                           # e.g. 'chain_broken', 'rolled_back'
    message: str
    backup_id: str | None = None
    file_path: str | None = None
    chunk_index: int | None = None
    chunk_hash: str | None = None


def validate_chain(
    repo_manifests: list[dict],
    witness_records: list[dict],
) -> list[Finding]:
    """Validate the hash chain and cross-check with the witness DB.

    Checks (per SPEC §4):
      1. Every manifest in the witness DB exists in the repo.
      2. ``prev_manifest_hash`` links are consistent.
      3. ``sequence_number`` values are strictly increasing (no gaps).
      4. The repo chain head matches the witness DB chain head.
      5. Sequence numbers in the repo match the witness DB.

    Args:
        repo_manifests: Manifest dicts loaded from the repo.
        witness_records: Rows from the witness DB ``manifests`` table.

    Returns:
        List of ``Finding`` objects (empty ⟹ chain is valid).
    """
    findings: list[Finding] = []

    # Sort repo manifests by sequence_number
    from r0nt.manifest import manifest_hash as compute_hash  # avoid circular at module level

    repo_sorted = sorted(repo_manifests, key=lambda m: m['sequence_number'])
    repo_by_id: dict[str, dict] = {m['backup_id']: m for m in repo_sorted}

    # Build hash → manifest lookup
    repo_hash_map: dict[str, dict] = {}
    for m in repo_sorted:
        repo_hash_map[compute_hash(m)] = m

    # ---- 1. Every witness record must exist in the repo ----
    for wr in witness_records:
        if wr['backup_id'] not in repo_by_id:
            findings.append(Finding(
                type='snapshot_missing',
                message=(
                    f"Manifest {wr['backup_id']} recorded in witness DB "
                    f"(seq {wr['sequence_number']}) is missing from the repo"
                ),
                backup_id=wr['backup_id'],
            ))

    # ---- 2. Chain links ----
    for m in repo_sorted:
        prev = m.get('prev_manifest_hash')
        seq = m['sequence_number']

        if seq == 1:
            if prev is not None:
                findings.append(Finding(
                    type='chain_broken',
                    message=(
                        f"First manifest {m['backup_id']} has non-null "
                        f"prev_manifest_hash: {prev}"
                    ),
                    backup_id=m['backup_id'],
                ))
        else:
            if prev is None:
                findings.append(Finding(
                    type='chain_broken',
                    message=(
                        f"Manifest {m['backup_id']} (seq {seq}) has null "
                        f"prev_manifest_hash but is not the first"
                    ),
                    backup_id=m['backup_id'],
                ))
            elif prev not in repo_hash_map:
                findings.append(Finding(
                    type='chain_broken',
                    message=(
                        f"Manifest {m['backup_id']} (seq {seq}) references "
                        f"prev_manifest_hash {prev} which is not in the repo"
                    ),
                    backup_id=m['backup_id'],
                ))

    # ---- 3. Sequence numbers strictly increasing ----
    for i in range(1, len(repo_sorted)):
        prev_seq = repo_sorted[i - 1]['sequence_number']
        curr_seq = repo_sorted[i]['sequence_number']
        if curr_seq != prev_seq + 1:
            findings.append(Finding(
                type='chain_broken',
                message=f"Sequence gap: {prev_seq} → {curr_seq}",
                backup_id=repo_sorted[i]['backup_id'],
            ))

    # ---- 4. Rollback / truncation detection ----
    if witness_records and repo_sorted:
        witness_head_seq = max(w['sequence_number'] for w in witness_records)
        repo_head_seq = max(m['sequence_number'] for m in repo_sorted)

        if repo_head_seq < witness_head_seq:
            findings.append(Finding(
                type='rolled_back',
                message=(
                    f"Repo chain head (seq {repo_head_seq}) is behind "
                    f"witness DB head (seq {witness_head_seq}) — "
                    f"possible rollback or truncation"
                ),
            ))

    # ---- 5. Sequence numbers match witness DB ----
    witness_by_id: dict[str, dict] = {w['backup_id']: w for w in witness_records}
    for wr in witness_records:
        bid = wr['backup_id']
        if bid in repo_by_id:
            repo_m = repo_by_id[bid]
            if repo_m['sequence_number'] != wr['sequence_number']:
                findings.append(Finding(
                    type='manifest_modified',
                    message=(
                        f"Manifest {bid}: sequence_number mismatch — "
                        f"repo={repo_m['sequence_number']}, "
                        f"witness={wr['sequence_number']}"
                    ),
                    backup_id=bid,
                ))

            # Cross-check manifest hash
            m_hash = compute_hash(repo_m)
            if not hmac_mod.compare_digest(m_hash, wr['manifest_hash']):
                findings.append(Finding(
                    type='manifest_modified',
                    message=(
                        f"Manifest hash mismatch for {bid}: "
                        f"repo={m_hash}, witness={wr['manifest_hash']}"
                    ),
                    backup_id=bid,
                ))

    return findings
