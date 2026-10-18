# r0nt Attack & Performance Evaluation Report

This document reports empirical measurements from the attack evaluation suite ([`eval/attacks.py`](../eval/attacks.py)) and performance benchmarking harness ([`eval/perf.py`](../eval/perf.py)) as mandated by **Phase 3 Specification §4**.

---

## 1. Executive Summary

* **Attack Coverage**: **11 of 11** in-scope attack scenarios were successfully and unambiguously detected by the verification pipeline and heuristics.
* **False Positive Rate**: **0%** (0 false positive findings across 20 consecutive clean backup and verification cycles).
* **Backup Throughput**: **~60.6 MB/s** on initial 100 MB backup; **~86.9 MB/s** on incremental backups.
* **Verification Throughput**:
  * **Quick Mode**: **~1,792 MB/s** (metadata, signatures, witness DB cross-check, chunk existence).
  * **Sample Mode (10%)**: **~781.8 MB/s** (deterministic sampling + full payload SHA-256).
  * **Full Mode**: **~161.5 MB/s** (100% chunk read, SHA-256 verification, two-level Merkle tree rebuild).
* **Storage Deduplication**: **~2.49x** deduplication efficiency on structured data; repository overhead is **~0.81x** of raw source volume due to chunk-level deduplication.

---

## 2. Attack Evaluation Results

Every scenario builds a synthetic fixture, simulates a realistic adversary capability, executes the verifier, and records detection and latency:

| Scenario ID | Threat Capability | Attack Description | Detected | Detection Mechanism | Finding(s) | Latency |
|-------------|-------------------|--------------------|:--------:|---------------------|------------|:-------:|
| **T-60.01** | Modifies backup data | 1-bit flip in stored content chunk | **YES** | Content SHA-256 verify | `chunk_modified` | 127.8 ms |
| **T-60.02** | Modifies backup data (deletion) | Deletes chunk file from store | **YES** | Chunk existence check | `chunk_missing` | 73.1 ms |
| **T-60.03** | Deletes a backup snapshot | Deletes intermediate manifest #1 | **YES** | Hash chain & witness cross-check | `snapshot_missing`, `chain_broken` | 92.1 ms |
| **T-60.04** | Rolls back to older snapshot | Removes latest snapshot #3 | **YES** | Sequence head comparison | `snapshot_missing`, `rolled_back` | 121.8 ms |
| **T-60.05** | Edits manifest without key | Modifies file metadata in JSON | **YES** | Ed25519 signature verify | `signature_invalid`, `manifest_modified` | 74.5 ms |
| **T-60.06** | Rewrites manifest & hashes | Recomputes Merkle root without private key | **YES** | Ed25519 signature verify | `signature_invalid`, `manifest_modified` | 79.5 ms |
| **T-60.07** | Compromised server + separate witness | Server resigns with unauthorized key | **YES** | Pinned public key & witness DB | `signature_invalid`, `manifest_modified` | 84.8 ms |
| **T-60.08** | Steals signing key | Forges snapshot directly in repo | **YES** | Witness DB cross-check | `file_added` (untracked) | 100.5 ms |
| **T-60.09** | Forges witness DB row | Direct SQLite row insertion | **YES** | HMAC-SHA256 row MAC | `manifest_modified` (bad MAC) | 89.9 ms |
| **T-60.10** | Backs up already-encrypted data | Pre-backup ransomware encryption | **YES\*** | Ransomware heuristics | `change_spike`, `extension_change` | 291.6 ms |
| **T-60.11** | Tampered anchor proof | Modifies external anchor proof BLOB | **YES** | Anchor backend attestation | `anchor_mismatch` | 98.0 ms |
| **T-60.12** | Compromises the verifier | Host OS binary patching | **N/A** | Out of software scope | `out_of_scope` | 0.0 ms |
| **T-60.13** | Physical storage failure | Hardware disk destruction | **N/A** | Out of software scope | `out_of_scope` | 0.0 ms |

*\*Note on T-60.10:* Pure cryptographic hash verification reports clean for pre-encrypted files because hashes match stored ciphertext. The attack is detected exclusively by r0nt's heuristic analyzers (`detect_change_spike`, `detect_extension_changes`, `detect_entropy_jumps`).

---

## 3. Honest Documentation of Misses & Known Boundaries

Per project hard rules, known limitations are published transparently:

1. **Pre-Backup Infection During Legitimate Runs (The "Authorized Key" Blindspot)**:
   If malware encrypts user files while the user is logged in, and the scheduled backup runs automatically with the legitimate private key and witness credentials, the cryptographic layer cannot detect this attack because the signatures and witness records are mathematically authentic. r0nt's defense is **heuristic**: `--fail-on-risk` causes the backup or verify pipeline to exit with non-zero status if entropy or extension anomalies are discovered.
2. **Verifier Host Compromise**:
   If an adversary obtains root access on the machine executing `r0nt verify`, the attacker can intercept system calls, falsify output, or replace the binary. Protection against verifier compromise requires architectural separation (running the verifier on a dedicated, hardened audit node).
3. **Same-Drive Co-Location**:
   When repository and witness DB are configured on the same filesystem volume, an attacker with write access can purge both. r0nt detects and logs a warning on execution, but cannot prevent physical file deletion.

---

## 4. False-Positive Evaluation

Normal file activities (adding files, updating documents, deleting old logs) must not raise integrity alarms.

* **Methodology**: 20 sequential incremental backup and verification cycles simulating typical user activity (creating new text files, appending to logs, modifying shared documents).
* **Result**:
  * Cycles executed: 20
  * False positive findings: 0
  * False positive rate: **0.0%**

---

## 5. Performance Benchmarks

Measured on standard development hardware (Windows 11, NVMe SSD, Python 3.12):

### 5.1 10 MB Dataset (25 files)
* **Source Size**: 10.0 MB
* **Repo Storage**: 8.30 MB (overhead ratio: 0.83x, deduplication ratio: 2.41x)
* **Initial Backup**: 0.17 s (**59.6 MB/s**)
* **Incremental Backup**: 0.12 s (**86.5 MB/s**)
* **Quick Verification**: 0.008 s (**1,249.2 MB/s**)
* **Sample Verification (10%)**: 0.011 s (**901.7 MB/s**)
* **Full Verification**: 0.073 s (**137.4 MB/s**)

### 5.2 100 MB Dataset (242 files)
* **Source Size**: 100.0 MB
* **Repo Storage**: 80.57 MB (overhead ratio: 0.81x, deduplication ratio: 2.49x)
* **Initial Backup**: 1.65 s (**60.6 MB/s**)
* **Incremental Backup**: 1.15 s (**86.9 MB/s**)
* **Quick Verification**: 0.056 s (**1,792.0 MB/s**)
* **Sample Verification (10%)**: 0.128 s (**781.8 MB/s**)
* **Full Verification**: 0.619 s (**161.5 MB/s**)

---

## 6. How to Reproduce

Run the automated evaluation suite locally:

```bash
# Run all 13 attack scenarios and generate eval/results.json
python eval/run_eval.py

# Run performance benchmark harness (10MB and 100MB)
python eval/perf.py --sizes 10 100

# Run full test suite including evaluation assertions
python -m pytest tests/test_eval.py -v
```
