# Ransomware-Aware Heuristics & Anomaly Detection

**r0nt** includes automated ransomware-aware heuristics designed to detect symptoms of malicious encryption or mass extortion attacks before they permanently compromise an entire backup history (SPEC_PHASE3 §2, DECISIONS.md D-12).

---

## 1. Design Philosophy

1. **Tamper-Evident, Not Tamper-Proof:** r0nt does not intercept or terminate running processes on the source filesystem. It analyzes snapshot transitions to provide early warning of anomalous file modifications.
2. **Flags, Never Verdicts:** Heuristic analyzers return structured `RiskFlag` instances (`low`, `medium`, or `high` severity) with concrete evidence. They never emit authoritative "ransomware" verdicts or block backup operations.
3. **Pure Functions Over Manifests:** Analysis operates deterministically on consecutive manifest pairs `(prev_manifest, curr_manifest)` combined with optional chunk sampling from the content-addressed store.
4. **False-Positive Resistance:** Benign operations (such as photo imports, dependency updates, and archive generation) must not trigger high-severity alerts.

---

## 2. Detection Rules & Formulations

### Rule 1: Change Spike Detection (`change_spike`)

Ransomware often modifies or destroys large numbers of files in a short time window. The change spike analyzer calculates the ratio of modified and removed files relative to the previous snapshot:

$$\text{ratio} = \frac{|\text{modified}| + |\text{removed}|}{|\text{previous\_files}|}$$

*Note: Newly added files do not count toward this ratio.*

#### Decision Logic:
- **With Historical Baseline ($\ge 3$ historical snapshots):**
  Computes sample mean $\mu$ and standard deviation $\sigma$ across prior change ratios.
  A flag triggers if:
  $$\text{ratio} > \mu + 2 \cdot \max(\sigma, 0.1) \quad \text{and} \quad \text{ratio} \ge 0.3$$
  - **High Severity:** $\text{ratio} \ge 0.75$
  - **Medium Severity:** $\text{ratio} < 0.75$
- **Fixed Threshold Fallback ($< 3$ snapshots):**
  Triggers if $\text{ratio} \ge 0.5$, marking the evidence with `confidence: "low_history"`.
  - **High Severity:** $\text{ratio} \ge 0.8$
  - **Medium Severity:** $\text{ratio} < 0.8$

---

### Rule 2: Extension Change Detection (`extension_change`)

Many ransomware strains append custom extensions (e.g., `.locked`, `.crypted`, `.enc`) or alter file extensions upon encryption.

#### Decision Logic:
The analyzer checks for deleted paths whose base stem or compound stem reappears under a new extension (e.g. `document.docx` $\rightarrow$ `document.docx.locked` or `report.txt` $\rightarrow$ `report.crypted`).
- Let $N_{\text{ext}}$ be the count of files converted to the most common new extension, and $R_{\text{ext}} = N_{\text{ext}} / |\text{previous\_files}|$.
- **Trigger Condition:** $N_{\text{ext}} \ge 5$ OR $R_{\text{ext}} \ge 0.20$ (20% of previous files).
- **Severity Classification:**
  - **High Severity:** $N_{\text{ext}} \ge 10$ OR $R_{\text{ext}} \ge 0.40$
  - **Medium Severity:** Otherwise.

---

### Rule 3: Entropy Jump Detection (`entropy_jump`)

Unencrypted files (such as source code, plain text, and configuration files) have relatively low Shannon entropy. High-grade ciphers (such as AES-256 or ChaCha20) produce ciphertext indistinguishable from random bytes, exhibiting maximal entropy near 8.0 bits/byte.

The Shannon entropy of byte sequence $X$ with byte frequencies $P(x_i)$ is:

$$H(X) = - \sum_{i=0}^{255} P(x_i) \log_2 P(x_i) \quad [0.0 \le H(X) \le 8.0]$$

#### Decision Logic:
1. Compares the first $N$ KiB (default: 64 KiB) of chunk data for modified files.
2. Identifies transitions where entropy jumps from $H_{\text{prev}} < 6.5$ (low) to $H_{\text{curr}} \ge 7.5$ (high).
3. **Trigger Condition:** At least 2 non-archive files experience an entropy jump.
   - **High Severity:** $\ge 5$ files affected.
   - **Medium Severity:** $2 \le \text{count} < 5$.

#### Skipped File Formats:
Files whose formats are inherently compressed or encrypted are skipped during entropy analysis:
- **Archives & Compressed Files:** `.zip`, `.7z`, `.gz`, `.tar`, `.bz2`, `.xz`, `.rar`, `.zst`
- **Images:** `.jpg`, `.jpeg`, `.png`, `.gif`, `.webp`, `.ico`
- **Audio & Video:** `.mp3`, `.mp4`, `.mkv`, `.avi`, `.mov`, `.flac`, `.ogg`
- **Documents & Packages:** `.pdf`, `.docx`, `.xlsx`, `.pptx`, `.odt`, `.ods`

---

## 3. False-Positive Analysis & Expected Behaviors

| Scenario | Expected Heuristic Behavior | Reason |
|---|---|---|
| **Photo Import** (e.g. adding 100 new JPEG/RAW photos) | **No flag emitted** | Adding new files leaves existing files untouched ($\text{ratio} = 0.0$); `.jpg`/`.png` are on the entropy skip list; no extensions were renamed. |
| **Compressing a Folder** (e.g. replacing files with `archive.zip`) | **No entropy jump** | `.zip` is on the entropy skip list; stems of removed files do not match `archive`. |
| **Software Update / Dependency Upgrade** (e.g. `npm install`, `pip install`) | **No flag emitted** | Modifying 20-30% of files in an active codebase falls within the rolling baseline ($\mu + 2\sigma$); source code transitions from low to low entropy. |
| **Legitimate Small File Conversion** (e.g. converting 1-2 `.docx` to `.pdf`) | **No extension flag** | Affected file count ($2 < 5$) falls below the extension change threshold. |
| **Editing Office Documents** (`.docx`, `.xlsx`) | **No entropy jump** | Office OpenXML documents are zip-compressed archives and are skipped by extension filter. |
| **Media Tagging & Transcoding** (e.g. modifying ID3 tags in MP3 files) | **No entropy jump** | `.mp3` and `.mp4` are on the entropy skip list. |
| **Bulk Addition of New Repositories** | **No change spike** | Only modified and removed files are counted in the numerator. |

---

## 4. Known Limitations & Threat Model Boundaries

1. **Slow-Burn Encryption:** Attackers encrypting files incrementally (e.g. 1-2 files per day) will not trigger the change spike or extension change thresholds.
2. **Pre-Encrypted Repositories:** Files encrypted prior to their initial introduction to r0nt exhibit high entropy on entry, but because they have no previous unencrypted version in the repository, no entropy jump can be observed.
3. **Renaming Without Encryption:** Mass renames without content alterations will trigger `extension_change` but will not trigger `entropy_jump`.

All heuristic findings are recorded in verify reports and CLI verify output for operator inspection.
