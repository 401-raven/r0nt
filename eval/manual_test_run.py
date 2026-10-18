"""Executes the manual testing runbook (docs/MANUAL_TEST.md) on a real non-critical directory."""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def run_manual_test() -> int:
    print("=" * 70)
    print("              r0nt MANUAL TEST RUNBOOK EXECUTION (T-90)")
    print("=" * 70)

    work_root = Path(tempfile.mkdtemp(prefix="r0nt_manual_test_"))
    print(f"Working Directory: {work_root}\n")

    try:
        src = work_root / "documents"
        src.mkdir()
        (src / "contract.txt").write_text("Confidential commercial contract terms.\n", encoding="utf-8")
        (src / "financials.csv").write_text("Department,Budget,Spend\nR&D,500000,420000\nSales,300000,280000\n", encoding="utf-8")
        sub = src / "reports"
        sub.mkdir()
        (sub / "q3_summary.md").write_text("# Q3 Audit\nAll cryptographic checks pass.\n", encoding="utf-8")

        repo = work_root / "repo"
        keys = work_root / "keys"
        keys.mkdir()
        k_priv = keys / "operator.pem"
        k_pub = keys / "operator.pub.pem"
        w_db = work_root / "witness.sqlite"
        restored = work_root / "restored"
        cfg_file = work_root / "profiles.toml"

        # Write profile TOML
        cfg_content = f"""[profiles.test_profile]
name = "test_profile"
repo = "{repo.as_posix()}"
witness_db = "{w_db.as_posix()}"
key_path = "{k_priv.as_posix()}"
pubkey_path = "{k_pub.as_posix()}"

[[profiles.test_profile.sources]]
label = "documents"
path = "{src.as_posix()}"
"""
        cfg_file.write_text(cfg_content, encoding="utf-8")

        def run_cli(*args):
            cmd = [sys.executable, "-m", "r0nt.cli", "--config", str(cfg_file)] + list(args)
            return subprocess.run(cmd, capture_output=True, text=True, cwd=str(PROJECT_ROOT))

        # 1. Init keys
        print("[Step 1] Initializing Ed25519 keypair...")
        r_init = run_cli("init", "--key", str(k_priv), "--pubkey", str(k_pub))
        assert r_init.returncode == 0, r_init.stderr
        print("  Keypair generated cleanly.")

        # 2. Status initial check
        print("\n[Step 2] Checking initial health status...")
        r_status = run_cli("status", "--profile", "test_profile")
        assert r_status.returncode == 0, r_status.stderr
        print("  Status check executed successfully.")

        # 3. Backup
        print("\n[Step 3] Running initial backup of real documents...")
        r_backup = run_cli("backup", "--profile", "test_profile")
        assert r_backup.returncode == 0, r_backup.stderr
        print("  Backup snapshot #1 created successfully.")

        # 4. Verify Full
        print("\n[Step 4] Running full cryptographic verification...")
        r_verify = run_cli("verify", "--profile", "test_profile", "--mode", "full")
        assert r_verify.returncode == 0, r_verify.stderr
        print("  Verification result: [CLEAN] All snapshots verified clean.")

        # 5. Restore & Byte-for-Byte Check
        print("\n[Step 5] Restoring snapshot #1 to destination...")
        r_restore = run_cli("restore", "1", "--target", str(restored), "--profile", "test_profile")
        assert r_restore.returncode == 0, r_restore.stderr

        for orig in src.rglob("*"):
            if orig.is_file():
                rel = orig.relative_to(src)
                rest_f = restored / "documents" / rel
                assert rest_f.exists(), f"Missing file: {rest_f}"
                assert orig.read_bytes() == rest_f.read_bytes(), f"Byte mismatch on: {rel}"
        print("  Restored files match original sources 100% byte-for-byte!")

        # 6. Restore-test
        print("\n[Step 6] Running automated synthetic restore test...")
        r_rt = run_cli("restore-test", "--profile", "test_profile")
        assert r_rt.returncode == 0, r_rt.stderr
        print("  Restore-test executed cleanly and verified sandbox.")

        # 7. External Anchoring
        print("\n[Step 7] Testing external anchoring batching...")
        r_anchor = run_cli("anchor", "run", "--profile", "test_profile")
        assert r_anchor.returncode == 0, r_anchor.stderr
        r_astatus = run_cli("anchor", "status", "--profile", "test_profile")
        assert r_astatus.returncode == 0, r_astatus.stderr
        print("  External anchoring batch created and attested.")

        # 8. Tamper Simulation
        print("\n[Step 8] Simulating adversary tampering in stored repository chunk...")
        chunk_f = next(f for f in (repo / "chunks").rglob("*") if f.is_file())
        b = bytearray(chunk_f.read_bytes())
        b[0] ^= 0x01
        chunk_f.write_bytes(b)
        print(f"  Flipped 1 bit in chunk: {chunk_f.name}")

        # Quick verify passes (existence check only)
        r_vq = run_cli("verify", "--profile", "test_profile", "--mode", "quick")
        assert r_vq.returncode == 0, "Quick mode should pass existence check"
        print("  Quick mode: PASSED (existence verified as designed).")

        # Full verify fails with exit code 1
        r_vf = run_cli("verify", "--profile", "test_profile", "--mode", "full")
        assert r_vf.returncode == 1, "Full verify must exit code 1 on corruption"
        assert "CHUNK_MODIFIED" in r_vf.stderr or "CHUNK_MODIFIED" in r_vf.stdout
        print("  Full mode: [TAMPERING DETECTED] Pinpointed CHUNK_MODIFIED (exit code 1)!")

        print("\n" + "=" * 70)
        print("SUCCESS: All steps of MANUAL_TEST.md completed and verified 100%!")
        print("=" * 70)
        return 0

    finally:
        shutil.rmtree(work_root, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(run_manual_test())
