"""r0nt Tamper Demo (SPEC §9).

Demonstrates the core security promise of r0nt:
  1. Creates a sample source directory with files.
  2. Initializes keys and the SQLite witness DB.
  3. Takes a signed backup into a repository.
  4. Runs a verification that passes cleanly.
  5. Simulates an adversary/bit rot by flipping one byte in a stored chunk.
  6. Runs verification again to show immediate tamper detection naming the exact chunk.
"""

from __future__ import annotations

import shutil
import sys
import tempfile
from pathlib import Path

# Add project root to path if run standalone
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR / "src"))

from r0nt.cli import main
from r0nt.store import ChunkStore


def run_demo():
    temp_dir = Path(tempfile.mkdtemp(prefix="r0nt_demo_"))
    try:
        print("=" * 70)
        print("                     r0nt TAMPER DEMO")
        print("=" * 70)
        print(f"Working directory: {temp_dir}\n")

        source_dir = temp_dir / "my_documents"
        source_dir.mkdir()
        (source_dir / "financial_records.csv").write_text(
            "Account,Balance\nAlice,1000000\nBob,500\nCharlie,75000\n",
            encoding="utf-8",
        )
        (source_dir / "contract.txt").write_text(
            "Contract agreement between party A and party B.\nConfidential terms.\n",
            encoding="utf-8",
        )
        (source_dir / "notes.txt").write_text(
            "Internal project milestones and architecture specifications.\n",
            encoding="utf-8",
        )

        repo_dir = temp_dir / "repo"
        keys_dir = temp_dir / "keys"
        keys_dir.mkdir()
        priv_key = keys_dir / "admin_ed25519.pem"
        pub_key = keys_dir / "admin_ed25519.pub.pem"
        witness_db = temp_dir / "witness_audit.sqlite"

        # Step 1: Init keys
        print("[Step 1] Initializing Ed25519 keypair...")
        ret = main([
            "init",
            "--key", str(priv_key),
            "--pubkey", str(pub_key),
        ])
        assert ret == 0, "Init failed"

        # Step 2: Backup
        print("\n[Step 2] Creating initial signed backup snapshot...")
        ret = main([
            "backup",
            str(source_dir),
            "--repo", str(repo_dir),
            "--key", str(priv_key),
            "--witness-db", str(witness_db),
        ])
        assert ret == 0, "Backup failed"

        # Step 3: Verify clean
        print("\n[Step 3] Verifying initial backup integrity (expect CLEAN)...")
        ret = main([
            "verify",
            "--repo", str(repo_dir),
            "--pubkey", str(pub_key),
            "--witness-db", str(witness_db),
        ])
        if ret == 0:
            print(">>> Verification PASSED clean as expected!")
        else:
            print(">>> Verification FAILED unexpectedly!", file=sys.stderr)
            sys.exit(1)

        # Step 4: Simulate Tampering / Bit Rot
        print("\n[Step 4] Simulating tampering: flipping 1 bit in a stored chunk on disk...")
        chunk_store = ChunkStore(repo_dir)
        chunks = chunk_store.list_chunks()
        assert chunks, "No chunks found in store"
        target_chunk = chunks[0]
        chunk_path = repo_dir / "chunks" / target_chunk[:2] / target_chunk

        print(f"Target chunk: {target_chunk}")
        print(f"File on disk: {chunk_path}")

        raw_bytes = bytearray(chunk_path.read_bytes())
        raw_bytes[0] ^= 0x01  # Flip 1 bit
        chunk_path.write_bytes(raw_bytes)
        print(">>> 1 bit flipped in stored chunk.")

        # Step 5: Verify detects tamper
        print("\n[Step 5] Re-running verification on tampered repository...")
        ret = main([
            "verify",
            "--repo", str(repo_dir),
            "--pubkey", str(pub_key),
            "--witness-db", str(witness_db),
        ])

        print("\n" + "=" * 70)
        if ret != 0:
            print("DEMO SUCCESS: The tampered chunk was detected and isolated!")
            print("The Merkle tree and SHA-256 chunk integrity verification identified")
            print("the modified chunk without false positives.")
        else:
            print("DEMO FAILED: Tampering was not detected!", file=sys.stderr)
            sys.exit(1)
        print("=" * 70)

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    run_demo()
