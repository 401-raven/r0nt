# r0nt Key Management Guide

## 1. Overview & Threat Model

r0nt uses **Ed25519** (asymmetric elliptic curve cryptography) for snapshot authentication and **HMAC-SHA256** for witness database integrity.

The trust model rests on a fundamental principle:
> **The private key MUST NEVER live on the backup repository server.**

If an attacker gains root or write access to the backup storage server, they can modify chunks, manifests, or rollback history. However, because they lack the private key:
1. They cannot forge a valid Ed25519 signature over modified manifest data.
2. The independent verifier, using the pinned public key and independent witness DB, will immediately detect any tampering, rollback, or deletion.

---

## 2. Where Keys Live

| Key / Artifact | Purpose | Allowed Storage Locations | Forbidden Locations |
|----------------|---------|---------------------------|---------------------|
| **Private Key** (`*.pem`) | Signs backup manifests during `r0nt backup` | Dedicated backup administration workstation, air-gapped machine, removable USB drive | **NEVER** on the backup target/repository server |
| **Public Key** (`*.pub.pem`) | Pinned by verifiers to authenticate manifests during `r0nt verify` and `r0nt restore` | Verifier hosts, audit machines, configuration repositories | Can be public |
| **Witness DB** (`*.db`) | Independent trust anchor recording backup sequence, hashes, and row MACs | Dedicated auditor host, workstation separate from the repo | **NEVER** on the backup server |
| **Witness MAC Key** | Protects witness SQLite rows from offline tampering | Derived from public key by default, or supplied via separate secret file | **NEVER** on the backup server |

### Permissions & File Protection
- On Unix/macOS: Private key files must have mode `0600` (owner read/write only).
- On Windows: Private key files receive owner-only restrictive ACLs (`icacls inheritance:r`).

---

## 3. Passphrase Protection (PKCS8 Encryption)

r0nt supports encrypting Ed25519 private keys at rest using the industry-standard PKCS8 `BestAvailableEncryption` provided by the Python `cryptography` library.

### Encrypting during Initialization
When initializing a keypair, pass `--encrypt` to prompt for a passphrase:
```bash
r0nt init --key /path/to/key.pem --pubkey /path/to/key.pub.pem --encrypt
```
You will be prompted for a passphrase with hidden terminal input.

### Passphrase Handling Rules
*   **Never on CLI**: `--passphrase` is not accepted as a command-line flag to prevent exposure in process lists, shell history, and logs.
*   **Interactive Input**: Uses `getpass` (masked terminal input).
*   **Automated / CI/CD Execution**: Non-interactive environments read the passphrase from the `R0NT_KEY_PASSPHRASE` environment variable.
*   **Plaintext Warning**: If an unencrypted key is used, r0nt logs and displays a clear warning in CLI output.

---

## 4. Key Utilities

### Inspecting Key Status
To check the fingerprint, encryption status, and permissions of your keys:
```bash
r0nt key info --profile <profile_name>
```
Output:
```
Key ID:      23d6f1550e8d0909
Private Key: C:\Users\user\.config\r0nt\key.pem
Public Key:  C:\Users\user\.config\r0nt\key.pub.pem
Encrypted:   True
```

### Exporting Public Keys
To safely export the pinned public key for audit nodes or verifiers without touching the private key:
```bash
r0nt key export-public /path/to/exported_key.pub.pem --profile <profile_name>
```

---

## 5. Key Rotation Approach

When a key needs to be rotated (e.g. routine security policy, staff change, or suspicion of compromise):

1. **Generate New Keypair**:
   Run `r0nt init` on the secure admin workstation with a new key path (e.g. `r0nt_2026.pem`).
2. **Update Profile**:
   Update `key_path` and `pubkey_path` in `profiles.toml` (or via `r0nt profile edit`).
3. **First Backup with New Key**:
   Run `r0nt backup`. The new manifest will reference the previous manifest's hash (`prev_manifest_hash`), preserving chain continuity across key generations.
4. **Verifier Trust Configuration**:
   Update the pinned public key on verifier nodes for subsequent backups.

---

## 6. What Happens If a Key Is Lost or Compromised

### Case A: Private Key is Lost (Unavailable)
- **Impact on Existing Backups**: None. All past snapshots remain 100% verifiable and readable using the pinned public key.
- **Impact on Future Backups**: No new backups can be signed with that key.
- **Remediation**:
  1. Generate a new keypair using `r0nt init`.
  2. Pin the new public key on verifier nodes.
  3. Resume backups; the new manifest links to the previous chain head via `prev_manifest_hash`.

### Case B: Private Key is Compromised (Stolen)
- **Impact**: An attacker possessing the private key and repository access can create validly signed rogue snapshots.
- **Detection**:
  - The witness DB detects rollback or reordering if the attacker attempts to rewrite existing history.
  - An attacker cannot alter existing snapshots already recorded in the witness DB without causing a hash mismatch or row MAC failure.
- **Remediation**:
  1. Immediately revoke the compromised key.
  2. Perform a full audit using `r0nt verify` against the independent witness DB to assess repo state.
  3. Generate a fresh keypair on clean infrastructure.
  4. Pin the new public key across all audit systems.

---

## 7. External Anchor Key (`anchor_key`)

r0nt uses a dedicated 256-bit symmetric key for external timestamp anchoring (e.g. OpenTimestamps / Bitcoin attestation):

*   **Privacy Blinding**: When anchoring batches of snapshot hashes, each leaf is computed as `HMAC-SHA256(anchor_key, manifest_hash)`. This ensures external observers of public blockchain transactions cannot test whether a specific document or snapshot hash exists in your backup history.
*   **Storage Location**: The anchor key is stored alongside the witness DB (e.g. `<witness_db>.anchor_key`) and strictly protected with owner-only filesystem permissions (`0600` on POSIX, owner ACLs on Windows). It is never written to repository files, manifests, or public logs.
*   **Independent Lifespan**: The anchor key is independent of the Ed25519 manifest signing key. Compromise of the signing key does not compromise anchor privacy.

