"""Ransomware-aware heuristics and anomaly detection (SPEC_PHASE3 §2, DECISIONS.md D-12).

Pure functions over consecutive manifest pairs and optional chunk sampling.
Outputs RiskFlag instances (low/medium/high) with concrete evidence;
never emits verdicts or blocks backups.
"""

from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass, field
from pathlib import PurePath
from typing import Any

from r0nt.store import ChunkStore

# Extensions that are inherently high-entropy (compressed, encrypted, or media).
# Skipped during entropy jump analysis to prevent false positives (SPEC_PHASE3 §2).
SKIP_ENTROPY_EXTENSIONS = {
    ".zip", ".7z", ".gz", ".tar", ".bz2", ".xz", ".rar", ".zst",
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".ico",
    ".mp3", ".mp4", ".mkv", ".avi", ".mov", ".flac", ".ogg",
    ".pdf", ".docx", ".xlsx", ".pptx", ".odt", ".ods",
}


@dataclass
class RiskFlag:
    """An indicator of potential anomaly or tampering risk."""
    kind: str  # "change_spike", "extension_change", "entropy_jump"
    severity: str  # "low", "medium", "high"
    score: float  # Normalized 0.0 to 1.0 confidence/intensity score
    evidence: dict[str, Any] = field(default_factory=dict)
    description: str = ""

    def __post_init__(self) -> None:
        if self.severity not in ("low", "medium", "high"):
            raise ValueError(f"Invalid severity '{self.severity}', must be low, medium, or high")
        self.score = max(0.0, min(1.0, float(self.score)))


def shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy in bits per byte [0.0, 8.0]."""
    if not data:
        return 0.0
    length = len(data)
    counts = Counter(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def detect_change_spike(
    prev_manifest: dict | None,
    curr_manifest: dict,
    history_change_ratios: list[float] | None = None,
    fixed_threshold: float = 0.5,
) -> RiskFlag | None:
    """Detect an anomalous spike in modified or removed files between snapshots.

    Uses a rolling history baseline when >= 3 historical ratios are provided;
    otherwise applies fixed thresholds with low/medium confidence.
    """
    if not prev_manifest:
        return None

    prev_files = {f["path"]: f.get("root_hash") for f in prev_manifest.get("files", [])}
    curr_files = {f["path"]: f.get("root_hash") for f in curr_manifest.get("files", [])}

    if not prev_files:
        return None

    modified = [p for p, h in curr_files.items() if p in prev_files and prev_files[p] != h]
    removed = [p for p in prev_files if p not in curr_files]
    changed_count = len(modified) + len(removed)
    total_prev = len(prev_files)
    ratio = changed_count / total_prev

    # Case A: Historical baseline available (>= 3 snapshots)
    if history_change_ratios and len(history_change_ratios) >= 3:
        avg = sum(history_change_ratios) / len(history_change_ratios)
        variance = sum((x - avg) ** 2 for x in history_change_ratios) / len(history_change_ratios)
        std_dev = math.sqrt(variance)

        # Trigger if current ratio is significantly above baseline
        if ratio > avg + 2 * max(std_dev, 0.1) and ratio >= 0.3:
            severity = "high" if ratio >= 0.75 else "medium"
            return RiskFlag(
                kind="change_spike",
                severity=severity,
                score=min(1.0, ratio),
                evidence={
                    "changed_files": changed_count,
                    "previous_files": total_prev,
                    "change_ratio": round(ratio, 3),
                    "baseline_avg": round(avg, 3),
                    "baseline_std": round(std_dev, 3),
                    "history_length": len(history_change_ratios),
                },
                description=(
                    f"Change spike detected: {changed_count}/{total_prev} files "
                    f"({round(ratio * 100, 1)}%) modified or removed, significantly exceeding "
                    f"historical average of {round(avg * 100, 1)}%."
                ),
            )
        return None

    # Case B: Fixed threshold (insufficient history)
    if ratio >= fixed_threshold:
        severity = "high" if ratio >= 0.8 else "medium"
        return RiskFlag(
            kind="change_spike",
            severity=severity,
            score=min(1.0, ratio * 0.8),  # slightly reduced score due to low history confidence
            evidence={
                "changed_files": changed_count,
                "previous_files": total_prev,
                "change_ratio": round(ratio, 3),
                "threshold": fixed_threshold,
                "history_length": len(history_change_ratios or []),
                "confidence": "low_history",
            },
            description=(
                f"Change spike (fixed threshold): {changed_count}/{total_prev} files "
                f"({round(ratio * 100, 1)}%) modified or removed."
            ),
        )

    return None


def detect_extension_changes(
    prev_manifest: dict | None,
    curr_manifest: dict,
    threshold_count: int = 5,
    threshold_ratio: float = 0.2,
) -> RiskFlag | None:
    """Detect widespread file extension changes or new ransomware-like extensions."""
    if not prev_manifest:
        return None

    prev_paths = [f["path"] for f in prev_manifest.get("files", [])]
    curr_paths = [f["path"] for f in curr_manifest.get("files", [])]

    if not prev_paths or not curr_paths:
        return None

    prev_set = set(prev_paths)
    curr_set = set(curr_paths)

    # Check for removed files whose base names reappear with a new extension
    prev_stems: dict[str, str] = {}
    for p in prev_paths:
        if p not in curr_set:
            path_obj = PurePath(p)
            prev_stems[path_obj.stem] = path_obj.suffix.lower()

    gained_extensions: list[str] = []
    renamed_pairs: list[dict[str, str]] = []

    for p in curr_paths:
        if p not in prev_set:
            path_obj = PurePath(p)
            stem = path_obj.stem
            # Check if this file was created from a previous stem (e.g. data.txt -> data.txt.locked or data.locked)
            if stem in prev_stems:
                ext = path_obj.suffix.lower()
                gained_extensions.append(ext)
                renamed_pairs.append({"before": f"{stem}{prev_stems[stem]}", "after": p})
            elif "." in stem:
                # Compound extensions, e.g. document.docx.crypted
                inner_stem = stem.rsplit(".", 1)[0]
                if inner_stem in prev_stems:
                    gained_extensions.append(path_obj.suffix.lower())
                    renamed_pairs.append({"before": f"{inner_stem}{prev_stems[inner_stem]}", "after": p})

    if not gained_extensions:
        return None

    ext_counts = Counter(gained_extensions)
    most_common_ext, common_count = ext_counts.most_common(1)[0]
    total_prev = len(prev_paths)
    ratio = common_count / max(1, total_prev)

    if common_count >= threshold_count or ratio >= threshold_ratio:
        severity = "high" if (common_count >= 10 or ratio >= 0.4) else "medium"
        return RiskFlag(
            kind="extension_change",
            severity=severity,
            score=min(1.0, ratio * 2),
            evidence={
                "extension": most_common_ext,
                "affected_files": common_count,
                "total_previous_files": total_prev,
                "ratio": round(ratio, 3),
                "samples": renamed_pairs[:5],
            },
            description=(
                f"Extension change detected: {common_count} files changed extension to '{most_common_ext}' "
                f"({round(ratio * 100, 1)}% of total files)."
            ),
        )

    return None


def detect_entropy_jumps(
    prev_manifest: dict | None,
    curr_manifest: dict,
    chunk_store: ChunkStore | None = None,
    sample_kb: int = 64,
    low_threshold: float = 6.5,
    high_threshold: float = 7.5,
    min_flagged_files: int = 2,
) -> RiskFlag | None:
    """Detect files transitioning from low entropy to high entropy (encryption symptom).

    Skips extensions that are normally high-entropy (zip, media, office archives)
    to prevent false positives.
    """
    if not prev_manifest or not chunk_store:
        return None

    prev_file_map = {f["path"]: f for f in prev_manifest.get("files", [])}
    curr_files = curr_manifest.get("files", [])

    flagged_files: list[dict[str, Any]] = []

    for cf in curr_files:
        path_str = cf["path"]
        if path_str not in prev_file_map:
            continue

        pf = prev_file_map[path_str]
        # Only inspect modified files
        if cf.get("root_hash") == pf.get("root_hash"):
            continue

        ext = PurePath(path_str).suffix.lower()
        if ext in SKIP_ENTROPY_EXTENSIONS:
            continue

        prev_chunks = pf.get("chunks", [])
        curr_chunks = cf.get("chunks", [])
        if not prev_chunks or not curr_chunks:
            continue

        # Sample initial chunks up to sample_kb KiB
        try:
            prev_first_hash = prev_chunks[0]["hash"]
            curr_first_hash = curr_chunks[0]["hash"]

            prev_data = chunk_store.read_chunk(prev_first_hash)[: sample_kb * 1024]
            curr_data = chunk_store.read_chunk(curr_first_hash)[: sample_kb * 1024]

            h_prev = shannon_entropy(prev_data)
            h_curr = shannon_entropy(curr_data)

            # Look for a jump from below low_threshold to above high_threshold
            if h_prev < low_threshold and h_curr >= high_threshold:
                flagged_files.append({
                    "path": path_str,
                    "entropy_before": round(h_prev, 2),
                    "entropy_after": round(h_curr, 2),
                    "jump": round(h_curr - h_prev, 2),
                })
        except Exception:
            continue

    if len(flagged_files) >= min_flagged_files:
        severity = "high" if len(flagged_files) >= 5 else "medium"
        return RiskFlag(
            kind="entropy_jump",
            severity=severity,
            score=min(1.0, len(flagged_files) / 10.0),
            evidence={
                "flagged_count": len(flagged_files),
                "samples": flagged_files[:5],
                "sample_kb": sample_kb,
            },
            description=(
                f"Entropy jump detected in {len(flagged_files)} non-archive files "
                f"(transitioned from low entropy < {low_threshold} to high entropy >= {high_threshold} bits/byte)."
            ),
        )

    return None


def analyze_snapshot_risk(
    prev_manifest: dict | None,
    curr_manifest: dict,
    chunk_store: ChunkStore | None = None,
    history_change_ratios: list[float] | None = None,
) -> list[RiskFlag]:
    """Execute all ransomware heuristic analyzers across a snapshot pair.

    Returns a list of RiskFlag objects (empty if no anomalies are detected).
    """
    flags: list[RiskFlag] = []

    spike = detect_change_spike(prev_manifest, curr_manifest, history_change_ratios)
    if spike:
        flags.append(spike)

    ext = detect_extension_changes(prev_manifest, curr_manifest)
    if ext:
        flags.append(ext)

    ent = detect_entropy_jumps(prev_manifest, curr_manifest, chunk_store)
    if ent:
        flags.append(ent)

    return flags
