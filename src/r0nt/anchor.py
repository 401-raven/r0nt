"""External anchoring subsystem (SPEC_PHASE3 §1, DECISIONS.md D-14).

Provides cryptographic timestamp proofs over batches of backup manifests,
preventing an attacker with total server compromise from rewriting history.
Uses privacy-preserving HMAC-SHA256 leaves so no manifest or file hashes
are disclosed publicly.
"""

from __future__ import annotations

import hashlib
import hmac as hmac_mod
import json
import os
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from r0nt.merkle import MerkleTree, ProofStep
from r0nt.store import WitnessDB


class AttestationStatus(str, Enum):
    """Result of external timestamp attestation verification."""
    VALID_CONFIRMED = "valid_confirmed"
    VALID_PENDING = "valid_pending"
    INVALID = "invalid"


class AnchorBackend(ABC):
    """Abstract interface for external timestamping / anchoring services."""

    @abstractmethod
    def submit(self, digest: bytes) -> bytes:
        """Submit a 32-byte batch root digest to external service.

        Returns raw serialized proof / receipt bytes.
        """
        ...

    @abstractmethod
    def upgrade(self, proof: bytes) -> bytes | None:
        """Attempt to fetch an updated confirmation proof from the external service.

        Returns upgraded proof bytes if confirmed, or None if still pending.
        """
        ...

    @abstractmethod
    def verify(self, proof: bytes, digest: bytes) -> AttestationStatus:
        """Verify that proof commits to the expected 32-byte digest."""
        ...


class FakeBackend(AnchorBackend):
    """Deterministic in-memory simulated anchor backend for tests and offline use."""

    def __init__(self, confirm_after_ticks: int = 1) -> None:
        self.confirm_after_ticks = confirm_after_ticks
        self.submissions: dict[bytes, dict[str, Any]] = {}
        self.simulate_network_failure: bool = False

    def submit(self, digest: bytes) -> bytes:
        if self.simulate_network_failure:
            raise ConnectionError("Simulated network connectivity failure")
        if len(digest) != 32:
            raise ValueError(f"Digest must be 32 bytes, got {len(digest)}")

        self.submissions[digest] = {
            "ticks": 0,
            "confirmed": False,
        }
        return b"FAKE_PROOF:" + digest + b":pending"

    def tick(self) -> None:
        """Advance simulated time/ticks for all pending submissions."""
        for digest, item in self.submissions.items():
            item["ticks"] += 1
            if item["ticks"] >= self.confirm_after_ticks:
                item["confirmed"] = True

    def confirm_all(self) -> None:
        """Force all pending submissions to confirmed state."""
        for item in self.submissions.values():
            item["confirmed"] = True

    def upgrade(self, proof: bytes) -> bytes | None:
        if self.simulate_network_failure:
            raise ConnectionError("Simulated network connectivity failure")
        digest = self._extract_digest(proof)
        if not digest:
            return None

        if digest in self.submissions:
            if self.submissions[digest]["confirmed"]:
                return b"FAKE_PROOF:" + digest + b":confirmed"
            return None

        # For stateless upgrades (e.g. separate CLI runs), upgrade pending fake proof
        return b"FAKE_PROOF:" + digest + b":confirmed"

    def verify(self, proof: bytes, digest: bytes) -> AttestationStatus:
        if not proof or not proof.startswith(b"FAKE_PROOF:"):
            return AttestationStatus.INVALID

        extracted = self._extract_digest(proof)
        if not extracted or not hmac_mod.compare_digest(extracted, digest):
            return AttestationStatus.INVALID

        if proof.endswith(b":confirmed"):
            return AttestationStatus.VALID_CONFIRMED
        if proof.endswith(b":pending"):
            return AttestationStatus.VALID_PENDING
        return AttestationStatus.INVALID

    @staticmethod
    def _extract_digest(proof: bytes) -> bytes | None:
        prefix = b"FAKE_PROOF:"
        if not proof or not proof.startswith(prefix):
            return None
        body = proof[len(prefix):]
        if body.endswith(b":pending"):
            digest = body[:-len(b":pending")]
        elif body.endswith(b":confirmed"):
            digest = body[:-len(b":confirmed")]
        else:
            return None
        return digest if len(digest) == 32 else None


def generate_anchor_key() -> bytes:
    """Generate a dedicated 256-bit cryptographic anchor key."""
    return os.urandom(32)


def compute_anchor_leaf(anchor_key: bytes, manifest_hash_hex: str) -> str:
    """HMAC-SHA256(anchor_key, manifest_hash) -> hex string.

    Keyed so external blockchain observers cannot determine whether a known
    manifest hash exists in the backup history (DECISIONS.md D-14).
    """
    return hmac_mod.new(
        anchor_key,
        manifest_hash_hex.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def build_anchor_batch(
    manifest_records: list[dict],
    anchor_key: bytes,
) -> tuple[str, list[dict]]:
    """Build a Merkle tree batch over unanchored manifests using keyed leaves.

    Args:
        manifest_records: List of manifest dicts ordered by sequence_number.
        anchor_key: 32-byte secret key for leaf HMAC derivation.

    Returns:
        (batch_root_hex, member_records_list)
    """
    if not manifest_records:
        raise ValueError("Cannot build an anchor batch from an empty manifest list")

    leaves_bytes: list[bytes] = []
    leaves_hex: list[str] = []

    for m in manifest_records:
        l_hex = compute_anchor_leaf(anchor_key, m["manifest_hash"])
        leaves_hex.append(l_hex)
        leaves_bytes.append(bytes.fromhex(l_hex))

    tree = MerkleTree(leaves_bytes)
    batch_root_hex = tree.root_hex

    member_records: list[dict] = []
    for idx, m in enumerate(manifest_records):
        proof_steps = tree.proof(idx)
        path_data = [
            {"hash": step.hash.hex(), "is_left": step.is_left}
            for step in proof_steps
        ]
        member_records.append({
            "sequence_number": m["sequence_number"],
            "manifest_hash": m["manifest_hash"],
            "leaf": leaves_hex[idx],
            "merkle_path": json.dumps(path_data),
        })

    return batch_root_hex, member_records


def run_anchor_batch(
    witness_db: WitnessDB,
    anchor_key: bytes,
    backend: AnchorBackend,
    backend_name: str = "fake",
) -> dict:
    """Collect unanchored manifests, construct batch, and submit to backend.

    If network connectivity fails, the batch is recorded with status 'skipped'
    and local operations are not blocked (DECISIONS.md D-14).
    """
    unanchored = witness_db.get_unanchored_manifests()
    if not unanchored:
        return {"status": "empty", "count": 0, "message": "No unanchored manifests found."}

    batch_root, members = build_anchor_batch(unanchored, anchor_key)
    created_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    try:
        proof = backend.submit(bytes.fromhex(batch_root))
        anchor_id = witness_db.record_anchor(
            batch_root=batch_root,
            leaf_count=len(members),
            backend=backend_name,
            proof=proof,
            status="pending",
            created_at=created_at,
        )
        for m in members:
            witness_db.record_anchor_member(
                anchor_id=anchor_id,
                sequence_number=m["sequence_number"],
                manifest_hash_val=m["manifest_hash"],
                leaf=m["leaf"],
                merkle_path=m["merkle_path"],
            )
        return {
            "status": "pending",
            "anchor_id": anchor_id,
            "batch_root": batch_root,
            "count": len(members),
            "backend": backend_name,
        }
    except Exception as exc:
        anchor_id = witness_db.record_anchor(
            batch_root=batch_root,
            leaf_count=len(members),
            backend=backend_name,
            proof=None,
            status="skipped",
            created_at=created_at,
        )
        for m in members:
            witness_db.record_anchor_member(
                anchor_id=anchor_id,
                sequence_number=m["sequence_number"],
                manifest_hash_val=m["manifest_hash"],
                leaf=m["leaf"],
                merkle_path=m["merkle_path"],
            )
        return {
            "status": "skipped",
            "anchor_id": anchor_id,
            "batch_root": batch_root,
            "count": len(members),
            "error": str(exc),
        }


def upgrade_anchors(witness_db: WitnessDB, backend: AnchorBackend) -> list[dict]:
    """Poll external service to upgrade pending anchors to confirmed state."""
    all_anchors = witness_db.get_all_anchors()
    upgraded_records: list[dict] = []

    for a in all_anchors:
        if a["status"] != "pending" or not a["proof"]:
            continue

        try:
            upgraded_proof = backend.upgrade(a["proof"])
            if upgraded_proof:
                conf_time = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                witness_db.update_anchor_status(
                    anchor_id=a["id"],
                    status="confirmed",
                    proof=upgraded_proof,
                    confirmed_at=conf_time,
                )
                upgraded_records.append({
                    "anchor_id": a["id"],
                    "batch_root": a["batch_root"],
                    "status": "confirmed",
                    "confirmed_at": conf_time,
                })
        except Exception:
            pass

    return upgraded_records


def verify_anchors(
    witness_db: WitnessDB,
    anchor_key: bytes,
    backend: AnchorBackend,
    anchor_grace_hours: int = 24,
) -> list[dict]:
    """Verify all external anchor batches, row MACs, proofs, and manifest inclusion.

    Returns:
        List of findings dictionaries with type, severity, and message.
    """
    findings: list[dict] = []
    anchors = witness_db.get_all_anchors()

    confirmed_manifest_seqs: set[int] = set()

    for a in anchors:
        aid = a["id"]
        # 1. Verify anchor row MAC
        if not witness_db.verify_anchor_row_mac(a):
            findings.append({
                "type": "anchor_mismatch",
                "severity": "danger",
                "anchor_id": aid,
                "message": f"Witness DB row MAC verification failed for anchor #{aid}.",
            })
            continue

        # Skip skipped/failed batches from cryptographic verification
        if a["status"] in ("skipped", "failed"):
            continue

        # 2. Verify backend attestation proof
        batch_root_bytes = bytes.fromhex(a["batch_root"])
        attestation = backend.verify(a["proof"], batch_root_bytes)

        if attestation == AttestationStatus.INVALID:
            findings.append({
                "type": "anchor_mismatch",
                "severity": "danger",
                "anchor_id": aid,
                "message": f"Proof verification failed for anchor #{aid} (invalid attestation).",
            })
            continue
        elif attestation == AttestationStatus.VALID_PENDING:
            findings.append({
                "type": "anchor_pending",
                "severity": "info",
                "anchor_id": aid,
                "message": f"Anchor #{aid} proof is pending external confirmation.",
            })

        # 3. Verify member rows, HMAC leaves, and Merkle tree root
        members = witness_db.get_anchor_members(aid)
        if len(members) != a["leaf_count"]:
            findings.append({
                "type": "anchor_mismatch",
                "severity": "danger",
                "anchor_id": aid,
                "message": f"Anchor #{aid} member count mismatch (expected {a['leaf_count']}, found {len(members)}).",
            })
            continue

        recomputed_leaves: list[bytes] = []
        members_valid = True

        for m in members:
            # Verify member row MAC
            if not witness_db.verify_anchor_member_row_mac(m):
                findings.append({
                    "type": "anchor_mismatch",
                    "severity": "danger",
                    "anchor_id": aid,
                    "sequence_number": m["sequence_number"],
                    "message": f"Row MAC failure for anchor member seq #{m['sequence_number']}.",
                })
                members_valid = False
                break

            # Recompute keyed leaf
            expected_leaf = compute_anchor_leaf(anchor_key, m["manifest_hash"])
            if not hmac_mod.compare_digest(expected_leaf, m["leaf"]):
                findings.append({
                    "type": "anchor_mismatch",
                    "severity": "danger",
                    "anchor_id": aid,
                    "sequence_number": m["sequence_number"],
                    "message": f"Keyed leaf mismatch for manifest seq #{m['sequence_number']}.",
                })
                members_valid = False
                break

            # Verify Merkle inclusion path
            try:
                path_steps = [
                    ProofStep(hash=bytes.fromhex(p["hash"]), is_left=p["is_left"])
                    for p in json.loads(m["merkle_path"])
                ]
                if not MerkleTree.verify_proof(bytes.fromhex(m["leaf"]), path_steps, batch_root_bytes):
                    findings.append({
                        "type": "anchor_mismatch",
                        "severity": "danger",
                        "anchor_id": aid,
                        "sequence_number": m["sequence_number"],
                        "message": f"Merkle inclusion proof invalid for manifest seq #{m['sequence_number']}.",
                    })
                    members_valid = False
                    break
            except Exception as exc:
                findings.append({
                    "type": "anchor_mismatch",
                    "severity": "danger",
                    "anchor_id": aid,
                    "message": f"Error parsing Merkle path for member seq #{m['sequence_number']}: {exc}",
                })
                members_valid = False
                break

            recomputed_leaves.append(bytes.fromhex(m["leaf"]))
            if a["status"] == "confirmed" and attestation == AttestationStatus.VALID_CONFIRMED:
                confirmed_manifest_seqs.add(m["sequence_number"])

        if members_valid and recomputed_leaves:
            recomputed_tree = MerkleTree(recomputed_leaves)
            if recomputed_tree.root_hex != a["batch_root"]:
                findings.append({
                    "type": "anchor_mismatch",
                    "severity": "danger",
                    "anchor_id": aid,
                    "message": f"Recomputed Merkle root {recomputed_tree.root_hex} does not match batch_root {a['batch_root']}.",
                })

    # 4. Check for manifests older than grace period that lack confirmed anchors
    now = datetime.now(timezone.utc)
    all_manifests = witness_db.get_all_records()

    for m in all_manifests:
        seq = m["sequence_number"]
        if seq in confirmed_manifest_seqs:
            continue

        try:
            created_dt = datetime.strptime(m["created_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
            age_hours = (now - created_dt).total_seconds() / 3600.0
            if age_hours > anchor_grace_hours:
                findings.append({
                    "type": "anchor_missing",
                    "severity": "warning",
                    "sequence_number": seq,
                    "backup_id": m["backup_id"],
                    "age_hours": round(age_hours, 1),
                    "message": f"Manifest seq #{seq} ({m['backup_id']}) is older than {anchor_grace_hours}h without confirmed anchor.",
                })
        except Exception:
            pass

    return findings
