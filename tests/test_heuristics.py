"""Synthetic-data unit tests for ransomware-aware heuristics (SPEC_PHASE3 §2, DECISIONS.md D-12)."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import pytest

from r0nt.heuristics import (
    RiskFlag,
    analyze_snapshot_risk,
    detect_change_spike,
    detect_entropy_jumps,
    detect_extension_changes,
    shannon_entropy,
)
from r0nt.store import ChunkStore


def _make_file_entry(path: str, root_hash: str, chunk_hash: str, size: int) -> dict:
    return {
        "path": path,
        "size": size,
        "mtime": "2026-10-18T00:00:00Z",
        "root_hash": root_hash,
        "chunks": [{"hash": chunk_hash, "size": size}],
    }


def test_shannon_entropy():
    # Empty data
    assert shannon_entropy(b"") == 0.0

    # Zero entropy: single repeating byte
    assert shannon_entropy(b"A" * 1024) == 0.0

    # Low entropy: English text
    english_text = (
        b"The quick brown fox jumps over the lazy dog. "
        b"Tamper-evident backup verification system with signed manifests."
    )
    ent_text = shannon_entropy(english_text)
    assert 4.0 <= ent_text <= 5.5

    # High entropy: pseudo-random bytes (simulating AES ciphertext)
    random_bytes = os.urandom(8192)
    ent_rand = shannon_entropy(random_bytes)
    assert ent_rand > 7.9  # Nearly maximum 8.0 bits/byte


def test_change_spike_normal_vs_anomaly():
    # 50 files baseline
    prev_files = [
        {"path": f"docs/file_{i}.txt", "root_hash": f"hash_{i}"}
        for i in range(50)
    ]
    prev_manifest = {"files": prev_files}

    # Case 1: Normal edit (2 files modified out of 50 -> 4%)
    curr_files_normal = list(prev_files)
    curr_files_normal[0] = {"path": "docs/file_0.txt", "root_hash": "new_hash_0"}
    curr_files_normal[1] = {"path": "docs/file_1.txt", "root_hash": "new_hash_1"}
    curr_manifest_normal = {"files": curr_files_normal}

    flag_normal = detect_change_spike(
        prev_manifest,
        curr_manifest_normal,
        history_change_ratios=[0.02, 0.04, 0.03, 0.05],
    )
    assert flag_normal is None

    # Case 2: Catastrophic change spike (45 out of 50 files modified -> 90%)
    curr_files_spike = [
        {"path": f"docs/file_{i}.txt", "root_hash": f"spiked_hash_{i}"}
        for i in range(50)
    ]
    curr_manifest_spike = {"files": curr_files_spike}

    flag_spike = detect_change_spike(
        prev_manifest,
        curr_manifest_spike,
        history_change_ratios=[0.02, 0.04, 0.03, 0.05],
    )
    assert flag_spike is not None
    assert flag_spike.kind == "change_spike"
    assert flag_spike.severity == "high"
    assert flag_spike.score >= 0.8
    assert flag_spike.evidence["changed_files"] == 50
    assert flag_spike.evidence["change_ratio"] == 1.0


def test_extension_changes_normal_vs_ransomware():
    prev_files = [
        {"path": f"Documents/report_{i}.docx"}
        for i in range(20)
    ]
    prev_manifest = {"files": prev_files}

    # Case 1: Normal single rename / extension change
    curr_files_normal = [
        {"path": f"Documents/report_{i}.docx"}
        for i in range(19)
    ] + [{"path": "Documents/report_19.pdf"}]
    curr_manifest_normal = {"files": curr_files_normal}

    flag_normal = detect_extension_changes(prev_manifest, curr_manifest_normal)
    assert flag_normal is None

    # Case 2: Ransomware mass-rename to .locked
    curr_files_locked = [
        {"path": f"Documents/report_{i}.locked"}
        for i in range(20)
    ]
    curr_manifest_locked = {"files": curr_files_locked}

    flag_locked = detect_extension_changes(prev_manifest, curr_manifest_locked)
    assert flag_locked is not None
    assert flag_locked.kind == "extension_change"
    assert flag_locked.severity == "high"
    assert flag_locked.evidence["extension"] == ".locked"
    assert flag_locked.evidence["affected_files"] == 20


def test_entropy_jump_detection_and_skip_rules(tmp_path: Path):
    store = ChunkStore(tmp_path / "repo")

    # Generate test payloads
    text_payload = b"Sample readable text file content. " * 50
    text_hash = hashlib.sha256(text_payload).hexdigest()
    store.write_chunk(text_hash, text_payload)

    text_payload_2 = b"Different readable text document. " * 50
    text_hash_2 = hashlib.sha256(text_payload_2).hexdigest()
    store.write_chunk(text_hash_2, text_payload_2)

    encrypted_payload_1 = os.urandom(2048)
    enc_hash_1 = hashlib.sha256(encrypted_payload_1).hexdigest()
    store.write_chunk(enc_hash_1, encrypted_payload_1)

    encrypted_payload_2 = os.urandom(2048)
    enc_hash_2 = hashlib.sha256(encrypted_payload_2).hexdigest()
    store.write_chunk(enc_hash_2, encrypted_payload_2)

    # 1. Normal edit on text file: text -> text (entropy remains low)
    prev_files = [
        _make_file_entry("src/data.txt", text_hash, text_hash, len(text_payload)),
        _make_file_entry("src/notes.txt", text_hash, text_hash, len(text_payload)),
    ]
    prev_manifest = {"files": prev_files}

    curr_files_normal = [
        _make_file_entry("src/data.txt", text_hash_2, text_hash_2, len(text_payload_2)),
        _make_file_entry("src/notes.txt", text_hash_2, text_hash_2, len(text_payload_2)),
    ]
    curr_manifest_normal = {"files": curr_files_normal}

    flag_normal = detect_entropy_jumps(prev_manifest, curr_manifest_normal, store)
    assert flag_normal is None

    # 2. Ransomware encryption attack: text -> random ciphertext (entropy jump)
    curr_files_attack = [
        _make_file_entry("src/data.txt", enc_hash_1, enc_hash_1, len(encrypted_payload_1)),
        _make_file_entry("src/notes.txt", enc_hash_2, enc_hash_2, len(encrypted_payload_2)),
    ]
    curr_manifest_attack = {"files": curr_files_attack}

    flag_attack = detect_entropy_jumps(prev_manifest, curr_manifest_attack, store)
    assert flag_attack is not None
    assert flag_attack.kind == "entropy_jump"
    assert flag_attack.evidence["flagged_count"] == 2

    # 3. Skip rule: .zip, .png, etc. must NOT flag even if entropy changes
    prev_files_zip = [
        _make_file_entry("backup/archive.zip", text_hash, text_hash, len(text_payload)),
        _make_file_entry("images/photo.jpg", text_hash, text_hash, len(text_payload)),
    ]
    curr_files_zip = [
        _make_file_entry("backup/archive.zip", enc_hash_1, enc_hash_1, len(encrypted_payload_1)),
        _make_file_entry("images/photo.jpg", enc_hash_2, enc_hash_2, len(encrypted_payload_2)),
    ]
    flag_zip = detect_entropy_jumps({"files": prev_files_zip}, {"files": curr_files_zip}, store)
    assert flag_zip is None


def test_analyze_snapshot_risk_composite(tmp_path: Path):
    store = ChunkStore(tmp_path / "repo")

    # Clean case
    f1 = _make_file_entry("data.txt", "h1", "h1", 100)
    flags_clean = analyze_snapshot_risk({"files": [f1]}, {"files": [f1]}, store)
    assert len(flags_clean) == 0

    # Multiple symptoms combined
    text_data = b"Clean notes and documentation." * 50
    text_hash = hashlib.sha256(text_data).hexdigest()
    store.write_chunk(text_hash, text_data)

    enc_data = os.urandom(2048)
    enc_hash = hashlib.sha256(enc_data).hexdigest()
    store.write_chunk(enc_hash, enc_data)

    prev_manifest = {
        "files": [
            _make_file_entry(f"docs/doc_{i}.txt", text_hash, text_hash, len(text_data))
            for i in range(10)
        ]
    }
    # Attacked: all files renamed to .enc with encrypted payload
    curr_manifest = {
        "files": [
            _make_file_entry(f"docs/doc_{i}.enc", enc_hash, enc_hash, len(enc_data))
            for i in range(10)
        ]
    }

    flags = analyze_snapshot_risk(
        prev_manifest,
        curr_manifest,
        store,
        history_change_ratios=[0.05, 0.05, 0.05],
    )
    kinds = {f.kind for f in flags}
    assert "change_spike" in kinds
    assert "extension_change" in kinds
