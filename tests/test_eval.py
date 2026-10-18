"""Automated tests for evaluation suite (T-60)."""

from __future__ import annotations

import json
from pathlib import Path
from eval.attacks import (
    attack_1_flip_chunk_byte,
    attack_2_delete_chunk,
    attack_3_delete_snapshot,
    attack_4_rollback_snapshot,
    attack_5_edit_manifest_without_key,
    attack_6_edit_manifest_and_hashes_without_key,
    attack_7_compromised_backup_server_witness_separate,
    attack_8_stolen_signing_key_forges_snapshot,
    attack_9_forged_witness_row,
    attack_10_pre_encrypted_data_ransomware,
    attack_11_tampered_anchor_proof,
)


def test_core_attack_scenarios():
    """Verify that every in-scope attack scenario detects the simulated threat."""
    r1 = attack_1_flip_chunk_byte()
    assert r1.detected
    assert "chunk_modified" in r1.findings

    r2 = attack_2_delete_chunk()
    assert r2.detected
    assert "chunk_missing" in r2.findings

    r3 = attack_3_delete_snapshot()
    assert r3.detected

    r4 = attack_4_rollback_snapshot()
    assert r4.detected
    assert "rolled_back" in r4.findings

    r5 = attack_5_edit_manifest_without_key()
    assert r5.detected
    assert "signature_invalid" in r5.findings

    r6 = attack_6_edit_manifest_and_hashes_without_key()
    assert r6.detected
    assert "signature_invalid" in r6.findings

    r7 = attack_7_compromised_backup_server_witness_separate()
    assert r7.detected
    assert "signature_invalid" in r7.findings

    r8 = attack_8_stolen_signing_key_forges_snapshot()
    assert r8.detected
    assert "file_added" in r8.findings

    r9 = attack_9_forged_witness_row()
    assert r9.detected

    r10 = attack_10_pre_encrypted_data_ransomware()
    assert r10.detected
    assert len(r10.findings) > 0

    r11 = attack_11_tampered_anchor_proof()
    assert r11.detected
    assert "anchor_mismatch" in r11.findings


def test_results_json_exists():
    """Ensure eval/results.json exists and contains structured evaluation output."""
    p = Path(__file__).resolve().parent.parent / "eval" / "results.json"
    assert p.exists()
    data = json.loads(p.read_text(encoding="utf-8"))
    assert "scenarios" in data
    assert len(data["scenarios"]) >= 11


def test_perf_benchmark():
    """Ensure performance measurement module executes properly and produces valid metrics."""
    from eval.perf import measure_performance
    res = measure_performance(size_mb=1.0)
    assert res.dataset_size_mb >= 1.0
    assert res.file_count > 0
    assert res.backup_initial_s > 0
    assert res.verify_full.duration_s > 0


def test_manual_test_runbook():
    """Verify that the end-to-end manual test runbook runs cleanly and detects tampering."""
    from eval.manual_test_run import run_manual_test
    rc = run_manual_test()
    assert rc == 0


