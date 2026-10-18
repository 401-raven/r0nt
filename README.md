# r0nt

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Integrity: Tamper-Evident](https://img.shields.io/badge/integrity-tamper--evident-green.svg)](#threat-model--security-guarantees)

**r0nt** is a cryptographic, tamper-evident backup verification system. It guarantees mathematical detection of silent data corruption (bit rot), ransomware modification, unauthorized file deletions, and snapshot rollback attacks.

> **Core Security Principle:**  
> **r0nt is tamper-evident, not tamper-proof.** It guarantees detection of tampering; it does not physically prevent an attacker with write access to storage media from altering or wiping disks. True protection requires pairing r0nt's independent witness verification with isolated or immutable storage.

---

## Table of Contents

- [Core Features](#core-features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Complete CLI Commands Reference](#complete-cli-commands-reference)
  - [1. `r0nt init` — Initialize Keypair](#1-r0nt-init--initialize-keypair)
  - [2. `r0nt status` — Health Dashboard](#2-r0nt-status--health-dashboard)
  - [3. `r0nt profile` — Profile Management](#3-r0nt-profile--profile-management)
  - [4. `r0nt backup` — Create Signed Snapshot](#4-r0nt-backup--create-signed-snapshot)
  - [5. `r0nt verify` — Cryptographic Verification](#5-r0nt-verify--cryptographic-verification)
  - [6. `r0nt restore` — File Restoration](#6-r0nt-restore--file-restoration)
  - [7. `r0nt restore-test` — Automated Restore Testing](#7-r0nt-restore-test--automated-restore-testing)
  - [8. `r0nt anchor` — External Blockchain Anchoring](#8-r0nt-anchor--external-blockchain-anchoring)
  - [9. `r0nt diff` — Compare Snapshots](#9-r0nt-diff--compare-snapshots)
  - [10. `r0nt list` & `r0nt show` — Inspect Snapshots](#10-r0nt-list--r0nt-show--inspect-snapshots)
  - [11. `r0nt key` — Key Utilities](#11-r0nt-key--key-utilities)
  - [12. `r0nt history` — Verification Log](#12-r0nt-history--verification-log)
  - [13. `r0nt schedule-help` — OS Automation Commands](#13-r0nt-schedule-help--os-automation-commands)
- [Configuration & Exclusion Guide](#configuration--exclusion-guide)
  - [Example `profiles.toml`](#example-profilestoml)
  - [Path Exclusion Rules](#path-exclusion-rules)
- [Architecture & Storage Internals](#architecture--storage-internals)
- [Threat Model & Security Guarantees](#threat-model--security-guarantees)
- [Exit Codes](#exit-codes)
- [Testing & Validation](#testing--validation)

---

## Core Features

* **Content-Addressable Deduplication**: Files are split into chunks hashed with SHA-256 (`repo/chunks/<first2>/<hash>`), ensuring identical data is stored only once across all snapshots.
* **Two-Level Merkle Trees**: Constructs per-file chunk Merkle trees and an aggregated backup-root Merkle tree, enabling exact chunk isolation upon corruption without scanning the entire repository.
* **Ed25519 Asymmetric Signatures**: Manifests are signed with an Ed25519 private key. Verification requires only a pinned public key; the private key never touches the backup repository.
* **Cryptographic Hash-Chaining**: Every snapshot embeds `prev_manifest_hash`, binding all backups into an append-only chain where deletions, replacements, or reordering break the chain.
* **Independent Witness Database**: SQLite database holding manifest records, anchor proofs, and HMAC-SHA256 row-level MACs (`row_mac`) to detect offline database tampering.
* **External Blockchain Anchoring**: Batches backup roots using HMAC-blinded leaves and commits them to the Bitcoin blockchain via OpenTimestamps for tamper-evident proof of existence.
* **Ransomware Heuristics**: Analyzes snapshots for pre-backup encryption using Shannon entropy transitions, mass extension modifications, and change-spike baselines.
* **Automated Sandbox Restore Testing**: Restores random sample files to an isolated sandbox and validates that files open correctly (ZIP integrity, SQLite PRAGMA checks, image headers, text encoding).
* **Profiles System**: Manage multiple backup sources, repos, and exclusion patterns under named profiles in user configuration.

---

## Installation

### Requirements
* Python 3.11+
* Operating Systems: Windows 10/11, Ubuntu/Debian/Linux, macOS

```bash
# Clone the repository
git clone https://github.com/401-raven/r0nt.git
cd r0nt

# Install in editable mode
pip install -e .
```

### Core Dependencies
| Dependency | Version | Purpose |
|---|---|---|
| `cryptography` | ≥ 41.0 | Ed25519 signatures, PKCS8 private key encryption |
| `platformdirs` | ≥ 4.0 | Cross-platform configuration, cache, and data paths |
| `tomli_w` | ≥ 1.0 | TOML profile serialization |

*(Optional)* For Bitcoin blockchain anchoring:
```bash
pip install opentimestamps
```

---

## Quick Start

### 1. Initialize an Encrypted Keypair
```bash
r0nt init --key ~/.ssh/r0nt_key.pem --pubkey ~/.ssh/r0nt_key.pub.pem --encrypt
```

### 2. Configure a Profile
Create a profile in your user configuration file (e.g., `%LOCALAPPDATA%\r0nt\profiles.toml` or `~/.config/r0nt/profiles.toml`):
```toml
[profiles.default]
name = "default"
repo = "D:/Backups/r0nt_repo"
witness_db = "E:/Auditing/witness.sqlite"
key_path = "C:/Users/user/.ssh/r0nt_key.pem"
pubkey_path = "C:/Users/user/.ssh/r0nt_key.pub.pem"

[[profiles.default.sources]]
label = "documents"
path = "C:/Users/user/Documents"
```

### 3. Check Initial System Health
```bash
r0nt status --profile default
```

### 4. Create Your First Backup
```bash
r0nt backup --profile default
```

### 5. Verify Backup Integrity
```bash
r0nt verify --profile default --mode full
```

### 6. Restore Files
```bash
r0nt restore 1 --target C:/RestoredFiles --profile default
```

---

## Complete CLI Commands Reference

All commands support the `--json` flag for machine-readable output and the `--config <path>` flag for custom profile file locations.

```
usage: r0nt [-h] [--json] [--config CONFIG]
            {init,backup,verify,restore,list,show,diff,profile,key,history,schedule-help,anchor,restore-test,status}
            ...
```

---

### 1. `r0nt init` — Initialize Keypair

Generates an Ed25519 keypair for signing backup manifests.

```bash
# Generate unencrypted keypair
r0nt init --key keys/priv.pem --pubkey keys/pub.pem

# Generate passphrase-encrypted keypair (recommended)
r0nt init --key keys/priv.pem --pubkey keys/pub.pem --encrypt

# Overwrite existing keys
r0nt init --key keys/priv.pem --pubkey keys/pub.pem --force
```

| Option | Description |
|---|---|
| `--key <path>` | Path to write the Ed25519 private key (saved with restrictive `0600`/owner permissions) |
| `--pubkey <path>` | Path to write the Ed25519 public key |
| `--encrypt` | Prompts for a passphrase via masked terminal input to encrypt the private key (PKCS8) |
| `-f`, `--force` | Overwrite existing key files |

---

### 2. `r0nt status` — Health Dashboard

Displays a consolidated, single-screen health overview of your backup system.

```bash
# Check status for default or specified profile
r0nt status --profile default

# Strict mode: exits with code 1 if any warning exists
r0nt status --profile default --strict
```

**Status Report Includes:**
* Total snapshots in repository and latest snapshot timestamp
* Hash-chain continuity status (`OK` / `BROKEN`)
* Last verification mode, result, and timestamp
* External anchoring status (batches submitted, pending, or confirmed)
* Last automated restore test outcome
* Active configuration warnings (e.g. witness DB co-located on repository drive, unencrypted private key, overdue backups)

---

### 3. `r0nt profile` — Profile Management

Manages named backup configurations.

```bash
# List all configured profile names
r0nt profile list

# Show detailed configuration for a profile
r0nt profile show default

# Set the active default profile (allows omitting --profile)
r0nt profile use default

# Remove a profile from configuration (does not delete repository files or keys)
r0nt profile remove old_profile
```

---

### 4. `r0nt backup` — Create Signed Snapshot

Scans configured source directories, splits files into content chunks, writes unique chunks, computes Merkle trees, signs the manifest, and updates the witness database.

```bash
# Run backup using a profile
r0nt backup --profile default

# Dry-run: simulate backup, showing chunks and sizes without disk writes
r0nt backup --profile default --dry-run

# Direct mode (without profile)
r0nt backup C:/Data --repo D:/Repo --key keys/priv.pem --witness-db E:/witness.sqlite

# Custom chunk size (e.g., 1MB)
r0nt backup --profile default --chunk-size 1048576
```

| Option | Description |
|---|---|
| `[source]` | Source directory path (used in direct mode) |
| `--profile <name>` | Named profile to execute |
| `--repo <path>` | Repository root directory (direct mode) |
| `--key <path>` | Path to private signing key (direct mode) |
| `--witness-db <path>` | Path to SQLite witness DB (direct mode) |
| `--chunk-size <bytes>` | Chunk size in bytes (default: 65,536 = 64KB) |
| `--dry-run` | Compute chunk stats without writing data |

---

### 5. `r0nt verify` — Cryptographic Verification

Validates stored repository chunks, manifests, hash-chains, and signatures against the independent witness DB.

```bash
# Full verification: reads every chunk and verifies SHA-256 hash (thorough)
r0nt verify --profile default --mode full

# Quick verification: checks signatures, chains, and chunk existence (fast)
r0nt verify --profile default --mode quick

# Sample verification: verifies a random sample of chunk payloads
r0nt verify --profile default --mode sample --percent 15.0

# Fail on risk: exit with code 1 if ransomware heuristics flag anomalies
r0nt verify --profile default --mode full --fail-on-risk
```

| Option | Description |
|---|---|
| `--profile <name>` | Profile name |
| `--mode {quick,full,sample}` | Verification depth (default: `full`) |
| `--percent <float>` | Chunk sample percentage for `sample` mode (default: `10.0`) |
| `--fail-on-risk` | Triggers exit code 1 if ransomware risk flags are raised |
| `--repo <path>` | Repository directory (direct mode) |
| `--pubkey <path>` | Pinned public key path (direct mode) |
| `--witness-db <path>` | Witness database path (direct mode) |

---

### 6. `r0nt restore` — File Restoration

Restores files from a specified snapshot after verifying the manifest's Ed25519 signature and cross-checking against the witness database.

```bash
# Restore snapshot #1 into destination directory
r0nt restore 1 --target C:/Restored --profile default

# Selective restore: restore only files matching a path prefix
r0nt restore 1 --target C:/Restored --profile default --path documents/finance

# Overwrite existing files in destination
r0nt restore 1 --target C:/Restored --profile default --allow-nonempty --overwrite
```

| Option | Description |
|---|---|
| `snapshot` | Snapshot sequence number (e.g. `1`) or UUID `backup_id` |
| `--target <path>` | Destination directory to restore files into (required) |
| `--profile <name>` | Profile name |
| `--path <prefix>` | Filter files to restore by canonical path prefix |
| `--allow-nonempty` | Allows restoration into a non-empty target directory |
| `--overwrite` | Overwrites pre-existing files in target directory |

---

### 7. `r0nt restore-test` — Automated Restore Testing

Selects a deterministic or random sample of files from the latest snapshot, restores them into an isolated sandbox, verifies SHA-256 chunk hashes, and tests that files open correctly according to format.

```bash
# Run restore test with default sample (20 files or 5%)
r0nt restore-test --profile default

# Test specific sample size
r0nt restore-test --profile default --sample 50

# Test specific percentage
r0nt restore-test --profile default --percent 10.0

# Specify custom temporary sandbox directory
r0nt restore-test --profile default --workdir C:/Sandbox
```

**Health Validations Performed:**
* **ZIP / Office Open XML (`.zip`, `.docx`, `.xlsx`)**: `zipfile.testzip()` integrity check
* **SQLite Databases (`.sqlite`, `.db`)**: `PRAGMA integrity_check(1)` execution
* **PDF Documents (`.pdf`)**: Header magic bytes `%PDF-` validation
* **Images (`.png`, `.jpg`, `.jpeg`)**: Magic byte signature verification
* **Text / Scripts (`.txt`, `.py`, `.json`, `.csv`)**: Strict UTF-8 decoding validation

---

### 8. `r0nt anchor` — External Blockchain Anchoring

Batches unanchored snapshot roots, blinds leaves with HMAC, and commits the batch Merkle root to the Bitcoin blockchain via OpenTimestamps.

```bash
# Batch and submit unanchored snapshot roots
r0nt anchor run --profile default

# Check attestation status of submitted batches
r0nt anchor status --profile default

# Fetch confirmations and upgrade pending proofs
r0nt anchor upgrade --profile default

# Cryptographically verify anchor proofs against the witness DB
r0nt anchor verify --profile default
```

---

### 9. `r0nt diff` — Compare Snapshots

Inspects differences between two snapshots (added, modified, deleted files, and deduplication delta).

```bash
# Compare snapshot 1 and snapshot 2
r0nt diff 1 2 --profile default

# Compare using UUID backup IDs
r0nt diff c9a3e6f1-... 7f201b4d-... --profile default
```

---

### 10. `r0nt list` & `r0nt show` — Inspect Snapshots

```bash
# List all snapshots in the repository
r0nt list --profile default

# Show detailed metadata and file entries for snapshot #1
r0nt show 1 --profile default
```

---

### 11. `r0nt key` — Key Utilities

```bash
# Inspect key fingerprint, permissions, and encryption status
r0nt key info --profile default

# Export public key for auditor or verifier deployment
r0nt key export-public /path/to/pinned_pubkey.pem --profile default
```

---

### 12. `r0nt history` — Verification Log

Displays the persistent audit log of all previous verification runs recorded in the witness DB.

```bash
r0nt history --profile default
```

---

### 13. `r0nt schedule-help` — OS Automation Commands

Generates copy-pasteable configuration commands for native operating system task schedulers.

```bash
r0nt schedule-help --profile default
```

**Outputs ready-to-run commands for:**
* **Windows Task Scheduler (`schtasks`)**: Daily backup, daily anchor batching, weekly full verification, weekly restore testing.
* **Linux / macOS (`cron`)**: Equivalent crontab job entries.

---

## Configuration & Exclusion Guide

Profiles are stored in standard platform locations:
* **Windows**: `%LOCALAPPDATA%\r0nt\profiles.toml`
* **Linux**: `~/.config/r0nt/profiles.toml`
* **macOS**: `~/Library/Application Support/r0nt/profiles.toml`

### Example `profiles.toml`

```toml
default_profile = "workstation"

[profiles.workstation]
name = "workstation"
repo = "D:/Backups/r0nt_repository"
witness_db = "E:/WitnessAudit/witness.sqlite"
key_path = "C:/Users/user/.ssh/r0nt_key.pem"
pubkey_path = "C:/Users/user/.ssh/r0nt_key.pub.pem"
chunk_size = 65536          # 64 KB chunk size (default)
max_file_size = 10737418240  # 10 GB limit per file
max_total_size = 107374182400# 100 GB limit per backup run
max_file_count = 500000     # Guard limit against directory loops

# Glob exclusion patterns
exclude = [
    "*.tmp",
    "*~",
    "*.swp",
    ".cache/**",
    ".git/**",
    "node_modules/**",
    "__pycache__/**",
    "$RECYCLE.BIN/**",
    "System Volume Information/**",
    "pagefile.sys",
    "hiberfil.sys",
    "swapfile.sys",
]

[[profiles.workstation.sources]]
label = "documents"
path = "C:/Users/user/Documents"

[[profiles.workstation.sources]]
label = "projects"
path = "C:/Users/user/Projects"
```

### Path Exclusion Rules
* Exclusions use standard Unix-style glob syntax matching canonical relative paths:
  * `*.tmp`: Matches any file ending in `.tmp` in any directory.
  * `node_modules/**`: Matches the `node_modules` directory and all nested subdirectories.
  * `build/*`: Matches files directly inside the `build` folder.
* **Security Guard:** Profiles explicitly forbid secrets storage. Configuration keys such as `passphrase`, `password`, `secret`, or `private_key_data` are blocked by `FORBIDDEN_CONFIG_KEYS`.

---

## Architecture & Storage Internals

```
r0nt/
├── src/r0nt/
│   ├── cli.py             # Thin CLI wrapper & argparse dispatcher
│   ├── service.py         # Domain services (Backup, Verify, Restore, Anchor, etc.)
│   ├── chunker.py         # Content-addressable chunking & SHA-256 hashing
│   ├── merkle.py          # Two-level RFC 6962 compliant Merkle trees
│   ├── chain.py           # Hash chain validation & sequence tracking
│   ├── manifest.py        # Canonical JSON serialization & signing
│   ├── signing.py         # Ed25519 signing, verification & PKCS8 encryption
│   ├── store.py           # ChunkStore, ManifestStore, and SQLite WitnessDB
│   ├── verify.py          # Quick, full, and sample verification pipeline
│   ├── restore.py         # Secure file restoration & path safety enforcement
│   ├── restoretest.py     # Automated sandbox restore testing & format checks
│   ├── anchor.py          # External anchoring & HMAC-SHA256 leaf blinding
│   ├── anchor_backends.py # OpenTimestamps & deterministic FakeBackend
│   ├── heuristics.py      # Shannon entropy & extension anomaly detection
│   ├── profile.py         # TOML profile persistence & validation
│   ├── diff.py            # Snapshot diffing & Merkle proof inspection
│   └── matcher.py         # Glob path pattern matching
├── tests/                 # Comprehensive unit & integration tests
├── eval/                  # Attack evaluation suite & performance benchmarks
├── docs/                  # Detailed engineering & operational documentation
└── scripts/               # Helper utilities & interactive tamper demo
```

### Storage Layout
* **Repository Storage (`repo/`)**:
  * `repo/chunks/<xx>/<sha256_hash>`: Read-only, content-addressed data chunks.
  * `repo/manifests/<backup_id>.json`: Canonical JSON manifest files written atomically.
* **Witness Database (`witness.sqlite`)**:
  * Independent ledger storing `manifests`, `anchors`, `anchor_members`, and `restore_test_history`.
  * Every row carries an `HMAC-SHA256` row MAC to prevent offline row injection or alteration.
  * **Co-Location Warning:** If the repository and witness DB reside on the same disk drive, r0nt alerts the operator that a compromised host could delete both.

---

## Threat Model & Security Guarantees

| Threat / Attacker Capability | Defense Mechanism | Verified Outcome |
|---|---|:---:|
| **Bit rot / chunk corruption** | SHA-256 chunk verification + Merkle tree recomputation | **DETECTED** (`chunk_modified`) |
| **Deleted chunk file** | Chunk existence validation during verification | **DETECTED** (`chunk_missing`) |
| **Deleted historical snapshot** | Hash chain link `prev_manifest_hash` + witness DB cross-check | **DETECTED** (`snapshot_missing`, `chain_broken`) |
| **Rollback attack (reverting to older snapshot)** | Monotonic sequence validation + witness DB head check | **DETECTED** (`rolled_back`) |
| **Altered manifest metadata** | Ed25519 digital signature over canonical manifest JSON | **DETECTED** (`signature_invalid`) |
| **Forged manifest & rebuilt Merkle tree** | Pinned public key verification (server lacks private key) | **DETECTED** (`signature_invalid`) |
| **Compromised server with rogue key** | Independent witness DB ledger check | **DETECTED** (`manifest_modified`, `file_added`) |
| **Injected rogue snapshot (stolen signing key)** | Witness DB cross-reference detects untracked snapshot | **DETECTED** (`file_added`) |
| **Direct SQLite witness DB tampering** | HMAC-SHA256 row-level MAC validation | **DETECTED** (`manifest_modified`) |
| **Pre-backup ransomware encryption** | Shannon entropy analysis & mass extension anomalies | **DETECTED** (`change_spike`, `extension_change`) |
| **External anchor tampering** | Merkle inclusion path & backend attestation verify | **DETECTED** (`anchor_mismatch`) |
| **Path traversal / zip-slip attacks** | Strict path normalization and sandbox root checking | **BLOCKED** (invalid path rejected) |

### Operational Boundaries (Out of Scope for Software Alone)
* **Verifier Host Compromise:** Software cannot verify itself if the operating system running the verifier is compromised. The verifier should run on an independent audit node.
* **Physical Hardware Failure:** Tamper-evidence guarantees detection of loss or damage, not recovery; maintain 3-2-1 backup redundancy across physical media.

---

## Exit Codes

`r0nt` commands return standard exit codes suitable for automated scripting:

| Code | Meaning |
|:---:|---|
| **`0`** | Clean execution — no integrity findings or corruption detected. |
| **`1`** | Integrity findings detected (chunk modified, missing snapshot, rollback, or `--fail-on-risk` trigger). |
| **`2`** | Usage error (invalid CLI flags, missing required options, bad configuration syntax). |
| **`3`** | Operational failure (I/O error, missing database file, disk full). |
| **`130`** | Operation cancelled by user (`SIGINT` / `Ctrl+C`). |

---

## Testing & Validation

### Run Full Test Suite
```bash
python -m pytest -q
```

### Run Threat-Model Attack Evaluation Suite
Executes 13 simulated attacks (bit flips, chunk deletions, manifest modifications, rogue injections, ransomware encryption, anchor corruption) and records empirical detection latency:
```bash
python eval/run_eval.py
```

### Run Performance Benchmarking
Measures backup and verification throughput across 10 MB and 100 MB synthetic datasets:
```bash
python eval/perf.py --sizes 10 100
```

### Run Interactive Tamper Demonstration
Runs an end-to-end live demonstration: creates a backup, verifies it clean, flips 1 bit in a stored chunk on disk, and demonstrates instant detection:
```bash
# On Windows
demo.bat

# On Linux / macOS
python scripts/tamper_demo.py
```
