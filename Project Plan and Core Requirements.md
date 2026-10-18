
### A tamper-evidence and verification system for backups, with optional external timestamping.

## 1. One-line idea

An independent system that records signed, timestamped fingerprints of every backup, and tells you when stored backups no longer match their history: modified, deleted, rolled back, or encrypted by ransomware.

## 2. Why this project

Backups fail quietly: silent corruption, ransomware that reaches the backups too, and restores that turn out not to work. Existing tools check a backup against its own metadata. An attacker who controls the backup server can change both together. This project adds an **independent witness** that the attacker on the backup server cannot rewrite.

**Positioning:** a tamper-evidence and verification layer, not "a blockchain backup system." It detects tampering; it does not prevent it.

## 3. What already exists (do not rebuild)

| Area                    | Existing tool                                          | What it does                                                                                                                                                                                               |
| ----------------------- | ------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Blockchain timestamping | OpenTimestamps                                         | Uses Bitcoin as a timestamp notary; batches hashes, so there is no one transaction per timestamp; confirmation takes a few hours; verifying proofs needs a local Bitcoin Core node (a pruned node is fine) |
| Integrity checking      | restic `check --read-data`, Borg `check --verify-data` | Verify stored data against checksums                                                                                                                                                                       |
| Deletion protection     | S3 Object Lock (compliance mode)                       | Prevents deletion or modification during the retention period, even by root                                                                                                                                |

Note: these facts came from project READMEs and community-written guides. Confirm against official documentation before relying on them.

**Known limit:** a matching hash does not prove the data was good. If ransomware encrypted files before the backup ran, the backup will verify perfectly.

## 4. The gap this project fills

1. An **external witness** holding signed, anchored fingerprints, so history cannot be quietly rewritten.
2. Detection of **deleted, replaced, or rolled-back snapshots**, not just corrupted bytes.
3. **Ransomware-aware checks** on backup contents.
4. **Automated restore tests**, since a backup that does not restore is the most common real failure.
5. A **measured evaluation** showing which attacks are caught and which are missed.

## 5. Threat model (write this first)

The threat model is the core deliverable. Fill in the last column honestly.

| Attacker capability                   | Example                               | Target outcome                                                    |
| ------------------------------------- | ------------------------------------- | ----------------------------------------------------------------- |
| Modifies backup data                  | Flips bytes in a stored chunk         | Detect, and identify which chunk                                  |
| Deletes a backup                      | Removes last week's snapshot          | Detect via hash chain gap                                         |
| Rolls back to an older snapshot       | Replaces the latest with an older one | Detect via chain and anchored history                             |
| Rewrites manifest and hashes together | Compromised backup server edits both  | Detect via signature and external anchor                          |
| Steals the signing key                | Attacker signs forged manifests       | Cannot detect after the fact; limit with key storage and rotation |
| Compromises the verifier              | Fake "all good" results               | Cannot detect; mitigate with separate host and credentials        |
| Backs up already-encrypted data       | Ransomware ran before the backup      | Heuristic detection only                                          |
| Physical storage failure              | Disk dies                             | Out of scope; needs redundancy                                    |

## 6. Base things to build: exact requirements

### 6.1 Chunking and hashing

- Split files into chunks (fixed-size first; content-defined chunking is a later upgrade).
- Hash each chunk with SHA-256.
- Record file path, size, modified time, and chunk list per file.

### 6.2 Merkle tree

- Build a Merkle tree over all chunk hashes.
- The **root hash** is the backup's fingerprint.
- Must support proving which chunks changed without re-reading everything.

### 6.3 Manifest

Each backup produces a manifest containing:

- backup ID and creation time
- root hash
- list of files with their chunk hashes
- **previous backup's manifest hash** (this forms the chain)
- tool and format version
- signature

### 6.4 Hash chain

- Every manifest includes the previous manifest's hash.
- Removing, reordering, or replacing an old backup breaks the chain and is detected.

### 6.5 Signing and key management

- Sign manifests with a key that is **not stored on the backup server**.
- Document where the key lives, how it is rotated, and what happens if it is lost.
- Use an established library (for example Ed25519). Do not invent cryptography.

### 6.6 External anchoring

- Batch root hashes and anchor them once per day using OpenTimestamps.
- Only hashes are published. Never publish backup contents.
- Consider keyed hashes (HMAC) so nobody can test whether a known file is in your backup.
- Handle the **pending window**: the newest backup is not anchored for a few hours. Document this clearly.

### 6.7 Independent verifier

- Runs on a **separate machine with separate credentials**.
- Recomputes hashes from the stored backup and compares them to signed manifests and anchored roots.
- Reports: modified, missing, added, rolled-back, chain broken, signature invalid, anchor mismatch.
- Names the exact chunk or file affected.

### 6.8 Ransomware-aware checks

- Spike in the number of files changed between backups.
- Mass file-extension changes.
- High-entropy file contents where the previous backup had low entropy.
- Output a risk flag, not a verdict. Heuristics produce false positives (compressed or encrypted files are normal in some folders).

### 6.9 Restore testing

- Restore a random sample to an isolated location.
- Check files exist, match their hashes, and open correctly.
- Run on a schedule and log results.

### 6.10 Interface

Start with a command line:

- `init`: set up keys and config
- `backup`: create backup, manifest, signature
- `anchor`: submit batched roots
- `verify`: run the independent check
- `restore-test`: sample restore
- `report`: human-readable and JSON results

### 6.11 Storage

- SQLite for manifests, chain state, anchor proofs, and verification history.

## 7. Decisions to make early

| Decision                                              | Options                                              | Recommendation                                                                                  |
| ----------------------------------------------------- | ---------------------------------------------------- | ----------------------------------------------------------------------------------------------- |
| Wrap an existing backup tool or write your own format | Wrap restic or Borg / own format                     | Wrap restic or Borg first: far less work, more realistic. Own format teaches more but is slower |
| Language                                              | Python / Go                                          | Python for speed of building; Go if you want a single binary                                    |
| Anchor method                                         | OpenTimestamps / testnet / trusted timestamp service | OpenTimestamps                                                                                  |
| Verifier location                                     | Same host / separate host                            | Separate host (required by the threat model)                                                    |

## 8. Non-goals (v1)

- Building a new blockchain or private chain (adds little if you control the nodes).
- Preventing tampering (pair with immutable or offline copies instead).
- Replacing restic, Borg, or enterprise backup products.
- Cloud accounts, dashboards, or multi-user features.
- Proving the original data was uncompromised.

## 9. Build plan (about 10 weeks)

| Weeks | Phase             | Deliverable                                          |
| ----- | ----------------- | ---------------------------------------------------- |
| 1     | Threat model      | Completed threat model table and design notes        |
| 2-3   | Core              | Chunking, Merkle tree, manifest, hash chain, signing |
| 4     | Anchoring         | Daily OpenTimestamps anchoring and proof storage     |
| 5-6   | Verifier          | Separate-host verifier with exact-chunk reporting    |
| 7     | Ransomware checks | Heuristics with documented false-positive behaviour  |
| 8     | Restore testing   | Scheduled sample restore and report                  |
| 9-10  | Attack evaluation | Attack scripts, results table, written findings      |

## 10. Acceptance criteria

- Modifying one byte in any stored chunk is detected and the chunk is identified.
- Deleting a snapshot is detected.
- Replacing the latest snapshot with an older one is detected.
- Editing a manifest without the signing key is detected.
- A manifest and hash edited together on the backup server is detected using the signature and external anchor.
- The verifier runs on a separate machine and still works if the backup server is fully compromised.
- A restore test fails visibly when files are missing or corrupted.
- Another person can install and run it using written instructions.

## 11. Evaluation plan (what makes this credible)

Write attack scripts for each row of the threat model. For every attack, record:

- detected or missed
- time to detection
- false positives on normal backups
- performance cost (backup time, verification time, storage overhead)

Publish the table, including the attacks you miss.

## 12. Risks

- The signing key and verifier become the main targets. Key management matters more than the blockchain.
- Pending timestamps leave a short unanchored window.
- Ransomware heuristics will produce false positives and false negatives.
- Large backups make full verification slow; plan sampling and incremental verification.
- Overclaiming. Say "tamper-evident," never "tamper-proof."

## 13. Open questions

- Wrap restic or Borg, or custom format?
- Python or Go?
- What backup size and number of files should it handle (laptop folder, small business server)?
- Who is the intended user: individual, small business, or students and researchers?
- Should anchoring be optional for offline use?

## 14. Next steps

1. Decide the wrap-versus-custom question.
2. Write the threat model (section 5) in your own words.
3. Build the chunk, Merkle tree, and manifest prototype on a small test folder.
4. Add a tamper script that flips one byte and shows the verifier catching it. This is the first demo.

## 15. References

- OpenTimestamps client: github.com/opentimestamps/opentimestamps-client
- restic documentation: restic.readthedocs.io
- AWS S3 Object Lock: docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html
- NIST CSF 2.0, RC.RP-03 (backup integrity verification)
