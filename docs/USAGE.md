# r0nt Usage Guide: Complete User Walkthrough

**r0nt** is a tamper-evident backup verification system designed to detect corruption, unauthorized alterations, deletions, and rollback attacks on backup repositories.

---

## 1. Installation

### Requirements
*   Python 3.11+
*   Dependencies: `cryptography`, `platformdirs`, `tomli_w`

Install `r0nt` in editable mode or into your virtual environment:

```bash
pip install -e .
```

---

## 2. CLI Interface

r0nt is purely command-line driven. Run `r0nt` or `r0nt --help` to view all available commands.

---

## 3. Profiles & Configuration

Profiles bundle all configuration for a backup job and are stored in your platform's user config directory (e.g. `%LOCALAPPDATA%\r0nt\profiles.toml` on Windows, or `~/.config/r0nt/profiles.toml` on Linux).

### Managing Profiles via CLI
```bash
# List all configured profiles
r0nt profile list

# Show profile details
r0nt profile show <profile_name>

# Remove a profile (never deletes repository files or keys)
r0nt profile remove <profile_name>
```

### Example `profiles.toml`
```toml
[profiles.default]
name = "default"
repo = "D:/Backups/r0nt_repo"
witness_db = "E:/Auditing/witness.db"
key_path = "C:/Users/username/.ssh/r0nt_key.pem"
pubkey_path = "C:/Users/username/.ssh/r0nt_key.pub.pem"
chunk_size = 1048576
max_file_size = 10737418240
max_total_size = 107374182400
max_file_count = 1000000
exclude = [
    "*.tmp",
    "*~",
    ".cache/**",
    "node_modules/**",
    ".git/**",
    "$RECYCLE.BIN/**",
    "System Volume Information/**",
    "pagefile.sys",
    "hiberfil.sys",
    "swapfile.sys",
]

[[profiles.default.sources]]
label = "Documents"
path = "C:/Users/username/Documents"

[[profiles.default.sources]]
label = "Photos"
path = "C:/Users/username/Pictures"
```

---

## 4. Backups

### Running a Backup
```bash
r0nt backup --profile default
```

### Dry Run (Simulation)
Calculate chunks, files, and total sizes without writing to disk:
```bash
r0nt backup --profile default --dry-run
```

### Output in JSON (for scripting/automation)
```bash
r0nt backup --profile default --json
```

---

## 5. Verification Modes

r0nt supports three verification modes:

### Quick Verification (`--mode quick`)
Checks witness DB row MACs, manifest Ed25519 signatures, hash chain links, and chunk **existence** without reading chunk data from disk. Ideal for frequent automated health checks:
```bash
r0nt verify --profile default --mode quick
```

### Full Verification (`--mode full`)
Reads every chunk payload from disk, validates its SHA-256 hash, and recomputes the entire two-level Merkle tree (per-file roots and backup root):
```bash
r0nt verify --profile default --mode full
```

### Sample Verification (`--mode sample --percent N`)
Performs all quick checks plus full cryptographic verification on a deterministic sample of chunks:
```bash
r0nt verify --profile default --mode sample --percent 15.0
```

---

## 6. Restoration

### Full Snapshot Restore
Restores all files from snapshot `1` to the target directory:
```bash
r0nt restore 1 --target C:\RestoredData --profile default
```

### Selective Restore (by Path Prefix)
Restores only files matching a specific prefix (e.g. `Documents/Reports`):
```bash
r0nt restore 1 --target C:\RestoredData --profile default --path Documents/Reports
```

### Overwrite & Target Directory Safety
*   Refuses non-empty destination directories unless `--allow-nonempty` is supplied:
    ```bash
    r0nt restore 1 --target C:\ExistingDir --profile default --allow-nonempty
    ```
*   Refuses overwriting pre-existing files unless `--overwrite` is supplied:
    ```bash
    r0nt restore 1 --target C:\ExistingDir --profile default --allow-nonempty --overwrite
    ```

---

## 7. Snapshot Inspection & Diffing

### Listing Snapshots
```bash
r0nt list --profile default
```

### Showing Snapshot Details
```bash
r0nt show 1 --profile default
```

### Comparing Two Snapshots
```bash
r0nt diff 1 2 --profile default
```

---

### Setting the Default Profile
Set a default profile so `--profile` can be omitted from subsequent commands:
```bash
r0nt profile use default
```

---

## 8. Status Dashboard (`r0nt status`)

Display a one-screen health summary of snapshots, hash-chain integrity, recent verifications, external anchors, restore testing, and operational warnings:
```bash
r0nt status --profile default
```
Use `--strict` to exit with code `1` if any health warnings exist (e.g., co-located witness DB, unencrypted key, or verification overdue):
```bash
r0nt status --profile default --strict
```

---

## 9. External Anchoring (`r0nt anchor`)

Batch and timestamp backup root hashes against external time-stamping notaries (e.g. OpenTimestamps / Bitcoin blockchain):

```bash
# Create and submit a batch of unanchored snapshots
r0nt anchor run --profile default

# Check anchor attestation status
r0nt anchor status --profile default

# Poll and upgrade pending anchor proofs
r0nt anchor upgrade --profile default

# Cryptographically verify anchor proofs against witness DB
r0nt anchor verify --profile default
```

---

## 10. Automated Restore Testing (`r0nt restore-test`)

Performs automated sample restorations into an isolated temporary directory, verifying chunk hashes and validating that files open correctly (ZIP integrity, SQLite PRAGMA check, image magic bytes, text encoding):

```bash
# Test a default random sample (20 files or 5%)
r0nt restore-test --profile default

# Test specific sample count or percentage on latest snapshot
r0nt restore-test --profile default --sample 50
r0nt restore-test --profile default --percent 10.0
```

---

## 11. Scheduled Automation Helper

To generate ready-to-paste scheduling commands for Windows Task Scheduler or cron:
```bash
r0nt schedule-help --profile default
```
Outputs:
*   Windows `schtasks` commands for automated daily backup, daily anchoring, weekly full verification, and weekly restore testing.
*   Linux/macOS `cron` entries.

---

## 12. Standard Exit Codes

*   `0`: Clean execution (no tampering or integrity findings).
*   `1`: Integrity findings detected (corruption, rollback, missing files, or `--fail-on-risk` heuristic trigger).
*   `2`: Usage or configuration error.
*   `3`: Operational failure (disk full, I/O error, missing database).
*   `130`: Operation cancelled by user.

