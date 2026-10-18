# r0nt Manual Testing Runbook (CLI Edition)

This runbook guides manual testing of r0nt on real-world folders using the command-line interface to validate backups, verification modes, restoration, anchoring, restore testing, and tamper detection.

---

## Pre-requisites
1. A real folder containing files (e.g. documents, images, nested subfolders).
2. A destination folder for the backup repository.
3. A separate folder or path for the witness DB and private key.

---

## Step-by-Step CLI Walkthrough

### Step 1: Initialize Keypair
Generate an Ed25519 signing keypair:
```bash
r0nt init --key <keys_dir>/r0nt_key.pem --pubkey <keys_dir>/r0nt_key.pub.pem
```
- [x] Confirm key files are created.
- [x] Verify restrictive permissions (0600 on POSIX, owner ACLs on Windows).

### Step 2: Profile & Health Status Check
Configure or inspect a profile and check initial health:
```bash
r0nt status --profile <profile_name>
```
- [x] Confirm clean one-screen status output displays snapshot count, chain health, and warnings (e.g. co-location or unencrypted key).

### Step 3: Run Initial Backup
Create the first signed backup snapshot:
```bash
r0nt backup <source_dir> --repo <repo_dir> --key <keys_dir>/r0nt_key.pem --witness-db <witness_dir>/witness.sqlite
```
- [x] Confirm progress and successful completion summary (Backup ID, sequence 1, chunk counts, root hash).

### Step 4: Verify Repository (Clean Run)
Run full cryptographic verification:
```bash
r0nt verify --repo <repo_dir> --pubkey <keys_dir>/r0nt_key.pub.pem --witness-db <witness_dir>/witness.sqlite --mode full
```
- [x] Confirm exit code is `0`.
- [x] Output reports: `[CLEAN] Verification Successful (Mode: FULL)`. No findings.

### Step 5: Test Restoration
Restore snapshot #1 into an isolated restore destination:
```bash
r0nt restore 1 --target <restore_target_dir> --repo <repo_dir> --pubkey <keys_dir>/r0nt_key.pub.pem --witness-db <witness_dir>/witness.sqlite
```
- [x] Confirm files are restored with original content and filenames.
- [x] Compare SHA-256 hashes of original vs restored files (100% byte fidelity).

### Step 6: Automated Restore Testing
Run synthetic restore testing on a sample:
```bash
r0nt restore-test --profile <profile_name>
```
- [x] Confirm random sample is restored to isolated sandbox, verified, and opened by type (ZIP, text, SQLite, images).
- [x] Confirm temporary sandbox is cleaned up.

### Step 7: External Anchoring
Batch and verify external timestamp anchors:
```bash
r0nt anchor run --profile <profile_name>
r0nt anchor status --profile <profile_name>
r0nt anchor verify --profile <profile_name>
```
- [x] Confirm batch root is computed and recorded.
- [x] Confirm proof verification passes cleanly.

### Step 8: Tamper Simulation & Detection
1. Locate a stored chunk in `<repo_dir>/chunks/<xx>/<hash>`.
2. Flip 1 bit in the chunk file:
   ```powershell
   $file = Get-ChildItem "<repo_dir>/chunks/*/*" | Select-Object -First 1
   $bytes = [System.IO.File]::ReadAllBytes($file.FullName)
   $bytes[0] = $bytes[0] -bxor 0x01
   [System.IO.File]::WriteAllBytes($file.FullName, $bytes)
   ```
3. Run **Quick** verification:
   ```bash
   r0nt verify --repo <repo_dir> --pubkey <keys_dir>/r0nt_key.pub.pem --witness-db <witness_dir>/witness.sqlite --mode quick
   ```
   - [x] Quick mode passes (it verifies chunk presence and chain integrity, not byte payload, as designed).
4. Run **Full** verification:
   ```bash
   r0nt verify --repo <repo_dir> --pubkey <keys_dir>/r0nt_key.pub.pem --witness-db <witness_dir>/witness.sqlite --mode full
   ```
   - [x] Exit code is `1`.
   - [x] Output displays `[TAMPERING DETECTED]`.
   - [x] Finding lists `CHUNK_MODIFIED`, identifying the exact chunk hash.
5. Attempt Restore:
   - [x] Restore aborts immediately upon encountering corrupted chunk hash, leaving no damaged file.
