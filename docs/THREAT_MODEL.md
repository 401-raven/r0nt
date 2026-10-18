# r0nt Threat Model & Security Evaluation

**System Classification**: Tamper-Evident Backup Verification Layer  
**Core Promise**: Guarantees prompt, cryptographic detection when backup history, snapshots, or chunk payloads are modified, rolled back, corrupted, or deleted.  
**Critical Boundary**: r0nt is **tamper-evident, not tamper-proof**. It reliably detects adversarial alterations; it does not physically prevent an attacker with write access to disks from deleting or modifying files.

---

## 1. Threat Model Table (Empirically Measured)

The table below corresponds to Section 5 of the project plan, with the final column filled in using empirical results from the automated evaluation suite ([`eval/results.json`](../eval/results.json)):

| Attacker Capability | Concrete Example | Defense Mechanism | Measured Target Outcome | Status |
|---------------------|------------------|-------------------|-------------------------|--------|
| **Modifies backup data** | Attacker or bit-rot flips 1 bit in a stored chunk | Content-addressable SHA-256 chunk storage + per-file Merkle tree | Detected in **127.8ms**. Pinpoints exact chunk hash mismatch with finding `chunk_modified`. Non-zero exit code (`1`). | **CAUGHT** |
| **Deletes stored data** | Attacker deletes a chunk file from repository storage | `ChunkStore.has_chunk()` validation during verification | Detected in **73.1ms**. Flags `chunk_missing` with exact chunk hash. | **CAUGHT** |
| **Deletes a backup snapshot** | Attacker removes intermediate snapshot #1 to purge historical records | Hash chain link `prev_manifest_hash` + independent witness DB cross-check | Detected in **92.1ms**. Flags `snapshot_missing` and `chain_broken`. | **CAUGHT** |
| **Rolls back to older snapshot** | Replaces repo head with older snapshot #2, hiding latest snapshot #3 | Sequence monotonicity check + witness DB head comparison | Detected in **121.8ms**. Flags `rolled_back` (repo seq 2 vs witness seq 3). | **CAUGHT** |
| **Edits manifest metadata** | Changes file size or timestamps in manifest JSON without private key | Ed25519 signature verification against pinned public key | Detected in **74.5ms**. Flags `signature_invalid`. | **CAUGHT** |
| **Rewrites manifest and hashes together** | Compromised backup server alters chunk and rebuilds Merkle root in manifest | Ed25519 digital signature over canonical manifest JSON | Detected in **79.5ms**. Flags `signature_invalid`. Internal hash consistency cannot forge asymmetric signature. | **CAUGHT** |
| **Compromised server with separate witness** | Compromised backup server generates new key and resigns altered repository | Independent witness DB holding signed history on auditor machine | Detected in **84.8ms**. Pinned public key flags `signature_invalid`; witness DB flags `manifest_modified`. | **CAUGHT** |
| **Steals the signing key** | Attacker acquires private key and injects forged snapshot directly into repo | Independent witness DB cross-check (`untracked_manifest` / `file_added`) | Detected in **100.5ms**. Injected snapshot is missing from witness ledger; flagged as `file_added`. | **CAUGHT (with limits)** |
| **Forges witness DB row** | Attacker directly inserts unauthorized row into witness SQLite database | HMAC-SHA256 row-level MACs (`row_mac`) derived from secret key | Detected in **89.9ms**. Flags `manifest_modified` ("Witness DB row MAC invalid"). | **CAUGHT** |
| **Backs up already-encrypted data** | Ransomware ran before backup, encrypting plaintext files into high-entropy ciphertext | Ransomware heuristics: entropy jumps, extension changes, change spikes | Detected in **291.6ms** by heuristics (`change_spike`, `extension_change`). **Cryptographic hash verification alone MISSES this** because hashes match ciphertext. | **HEURISTIC CATCH** |
| **Alters external timestamp proof** | Adversary tampers with external anchor proof BLOB in witness DB | Merkle inclusion proof + backend attestation verification | Detected in **98.0ms**. Flags `anchor_mismatch`. | **CAUGHT** |
| **Compromises the verifier** | Attacker compromises verifier machine and modifies binary to exit 0 | Out of software scope. Requires architectural and operational isolation. | **Cannot detect via software.** Software cannot verify its own runtime on a compromised OS. Mitigated by hosting verifier on an air-gapped or dedicated read-only auditor node. | **OUT OF SCOPE** |
| **Physical storage failure** | Storage disk completely dies or suffers unrecoverable head crash | Out of software scope. Requires multi-site hardware redundancy. | **Cannot recover data.** Tamper-evidence detects integrity violations; availability requires 3-2-1 backup architecture with offsite replicas. | **OUT OF SCOPE** |

---

## 2. Detailed Threat Analysis & Limitations

### 2.1 Stolen Signing Key (Known Limit)
* **What is caught**: If an adversary obtains the private key and signs an unauthorized snapshot directly into the repository storage, the verifier running with an independent witness DB immediately catches the rogue snapshot because it was never recorded in the witness DB (finding `file_added`).
* **What is NOT caught**: If an attacker steals the private key and compromises the backup client *before* the scheduled backup runs, malicious data signed by the legitimate client during a scheduled run will have a cryptographically valid signature and valid witness DB record. In this scenario, cryptographic verification passes; detection relies entirely on **ransomware heuristics** (e.g., sudden entropy spikes or mass extension changes).

### 2.2 Pre-Encrypted Data / Ransomware (Known Limit of Pure Hashing)
* Hashing and Merkle trees verify that stored data matches what was backed up.
* If files were already encrypted by ransomware prior to chunking, the chunk hashes and Merkle root are mathematically authentic.
* To bridge this critical gap, r0nt implements heuristic analyzers ([`heuristics.py`](../src/r0nt/heuristics.py)):
  1. **Shannon Entropy Analysis**: Flags transitions from low entropy (< 6.5 bits/byte) to high entropy (> 7.5 bits/byte) across modified files.
  2. **Extension Anomaly Detection**: Flags files renamed to known ransomware extensions or mass uniform extension shifts.
  3. **Change Spike Baseline**: Flags sudden spikes where changed file count radically exceeds historical baseline.

### 2.3 Co-location Warning
* If the repository and witness database reside on the same filesystem volume (e.g., both on `C:`), an attacker with root/administrator access can delete both simultaneously.
* r0nt issues a prominent warning during CLI operations when co-location is detected:
  ```
  Notice: Warning: Witness DB is on the same drive (C:) as repository (C:). An attacker controlling this machine can modify both.
  ```
* For true tamper-evidence, store the witness DB on a separate physical machine, write-once media, or a secured auditing host.
