"""False-positive test suite for ransomware-aware heuristics (SPEC_PHASE3 §2, T-31).

Verifies that benign user workflows (photo imports, software/dependency updates,
compressing directories, media tagging, legitimate small renames, bulk additions)
do not trigger spurious high-severity risk flags.
"""

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


def _make_file_entry(
    path: str,
    root_hash: str,
    chunk_hash: str | None = None,
    size: int = 1024,
) -> dict:
    c_hash = chunk_hash or root_hash
    return {
        "path": path,
        "size": size,
        "mtime": "2026-10-18T10:00:00Z",
        "root_hash": root_hash,
        "chunks": [{"hash": c_hash, "size": size}],
    }


def test_photo_import_benign(tmp_path: Path):
    """Importing 80 high-entropy photos into an existing profile must not trigger any flags."""
    store = ChunkStore(tmp_path / "repo")

    # Baseline: 20 existing text files
    text_data = b"Meeting notes and quarterly financial summaries.\n" * 40
    text_hash = hashlib.sha256(text_data).hexdigest()
    store.write_chunk(text_hash, text_data)

    prev_files = [
        _make_file_entry(f"documents/doc_{i}.txt", text_hash, text_hash, len(text_data))
        for i in range(20)
    ]
    prev_manifest = {"files": prev_files}

    # User imports 80 JPEG/PNG photos (simulated high entropy data)
    curr_files = list(prev_files)
    for i in range(80):
        photo_bytes = os.urandom(4096)
        photo_hash = hashlib.sha256(photo_bytes).hexdigest()
        store.write_chunk(photo_hash, photo_bytes)
        ext = ".jpg" if i % 2 == 0 else ".png"
        curr_files.append(
            _make_file_entry(f"photos/2026_vacation/img_{i:03d}{ext}", photo_hash, photo_hash, len(photo_bytes))
        )

    curr_manifest = {"files": curr_files}

    # Analysis across all heuristic analyzers
    flags = analyze_snapshot_risk(
        prev_manifest=prev_manifest,
        curr_manifest=curr_manifest,
        chunk_store=store,
        history_change_ratios=[0.05, 0.04, 0.06],
    )

    # Adding new files does not touch previous files, so change_spike is 0.0.
    # Photo extensions are skipped by entropy jump.
    # No existing files were renamed.
    assert flags == [], f"Expected 0 flags for photo import, got: {flags}"


def test_compress_folder_into_archive(tmp_path: Path):
    """Replacing a folder of text documents with a compressed archive must not trigger entropy jump."""
    store = ChunkStore(tmp_path / "repo")

    text_data = b"Source code and markdown text documentation." * 50
    text_hash = hashlib.sha256(text_data).hexdigest()
    store.write_chunk(text_hash, text_data)

    # 15 text files in project/
    prev_files = [
        _make_file_entry(f"project/module_{i}.py", text_hash, text_hash, len(text_data))
        for i in range(15)
    ]
    prev_manifest = {"files": prev_files}

    # User compresses the project into a single project_archive.zip (high entropy)
    # and removes the individual python files
    zip_bytes = os.urandom(8192)  # Compressed archives exhibit high Shannon entropy
    zip_hash = hashlib.sha256(zip_bytes).hexdigest()
    store.write_chunk(zip_hash, zip_bytes)

    curr_files = [
        _make_file_entry("project_archive.zip", zip_hash, zip_hash, len(zip_bytes))
    ]
    curr_manifest = {"files": curr_files}

    # 1. Entropy jump analyzer must NOT flag the .zip file
    ent_flag = detect_entropy_jumps(prev_manifest, curr_manifest, store)
    assert ent_flag is None

    # 2. Extension change analyzer must NOT flag because the stems don't match
    ext_flag = detect_extension_changes(prev_manifest, curr_manifest)
    assert ext_flag is None


def test_software_update_dependencies(tmp_path: Path):
    """Software dependencies or code updates with moderate changes within history baseline."""
    store = ChunkStore(tmp_path / "repo")

    # 100 source code files in a software repository
    code_v1 = b"import sys\nimport os\ndef run():\n    print('version 1.0')\n" * 20
    hash_v1 = hashlib.sha256(code_v1).hexdigest()
    store.write_chunk(hash_v1, code_v1)

    code_v2 = b"import sys\nimport os\ndef run():\n    print('version 2.0')\n" * 20
    hash_v2 = hashlib.sha256(code_v2).hexdigest()
    store.write_chunk(hash_v2, code_v2)

    prev_files = [
        _make_file_entry(f"src/pkg/module_{i}.py", hash_v1, hash_v1, len(code_v1))
        for i in range(100)
    ]
    prev_manifest = {"files": prev_files}

    # 25 files updated during dependency/library upgrade (25% change ratio)
    curr_files = list(prev_files)
    for i in range(25):
        curr_files[i] = _make_file_entry(f"src/pkg/module_{i}.py", hash_v2, hash_v2, len(code_v2))
    curr_manifest = {"files": curr_files}

    # Baseline reflects an active development repo with ~20-30% churn
    history_ratios = [0.22, 0.28, 0.24, 0.26]

    flags = analyze_snapshot_risk(
        prev_manifest=prev_manifest,
        curr_manifest=curr_manifest,
        chunk_store=store,
        history_change_ratios=history_ratios,
    )

    assert flags == [], f"Expected clean pass for normal dev churn, got {flags}"


def test_legitimate_small_file_conversions():
    """Legitimate conversion of 2 files (e.g. DOCX -> PDF) must stay below extension change threshold."""
    prev_files = [
        {"path": f"contracts/contract_{i}.docx", "root_hash": f"h_{i}"}
        for i in range(40)
    ]
    prev_manifest = {"files": prev_files}

    # User converts 2 contracts to PDF
    curr_files = [
        {"path": f"contracts/contract_{i}.docx", "root_hash": f"h_{i}"}
        for i in range(38)
    ] + [
        {"path": "contracts/contract_38.pdf", "root_hash": "pdf_38"},
        {"path": "contracts/contract_39.pdf", "root_hash": "pdf_39"},
    ]
    curr_manifest = {"files": curr_files}

    flag = detect_extension_changes(
        prev_manifest,
        curr_manifest,
        threshold_count=5,
        threshold_ratio=0.2,
    )
    assert flag is None


def test_media_tag_updates_skipped(tmp_path: Path):
    """Editing MP3 tags or video metadata changes chunk contents but must skip entropy jump."""
    store = ChunkStore(tmp_path / "repo")

    # Compressed MP3 audio bytes (high entropy originally)
    mp3_v1 = os.urandom(4096)
    hash_v1 = hashlib.sha256(mp3_v1).hexdigest()
    store.write_chunk(hash_v1, mp3_v1)

    # Re-tagged MP3 audio bytes (still high entropy)
    mp3_v2 = os.urandom(4096)
    hash_v2 = hashlib.sha256(mp3_v2).hexdigest()
    store.write_chunk(hash_v2, mp3_v2)

    prev_manifest = {
        "files": [
            _make_file_entry(f"music/track_{i}.mp3", hash_v1, hash_v1, len(mp3_v1))
            for i in range(10)
        ]
    }
    curr_manifest = {
        "files": [
            _make_file_entry(f"music/track_{i}.mp3", hash_v2, hash_v2, len(mp3_v2))
            for i in range(10)
        ]
    }

    flag = detect_entropy_jumps(prev_manifest, curr_manifest, store)
    assert flag is None


def test_pure_addition_spikes_no_change_spike():
    """Adding 500 new files to an existing 10-file repository is not a change spike."""
    prev_files = [{"path": f"notes_{i}.txt", "root_hash": f"h_{i}"} for i in range(10)]
    prev_manifest = {"files": prev_files}

    curr_files = list(prev_files) + [
        {"path": f"new_files/item_{i}.txt", "root_hash": f"new_{i}"}
        for i in range(500)
    ]
    curr_manifest = {"files": curr_files}

    flag = detect_change_spike(
        prev_manifest,
        curr_manifest,
        history_change_ratios=[0.05, 0.05, 0.05],
    )
    assert flag is None


def test_office_document_edits_skipped(tmp_path: Path):
    """Editing Word/Excel documents (.docx/.xlsx) modifies zip-compressed contents but skips entropy jump."""
    store = ChunkStore(tmp_path / "repo")

    doc_v1 = os.urandom(2048)
    hash_v1 = hashlib.sha256(doc_v1).hexdigest()
    store.write_chunk(hash_v1, doc_v1)

    doc_v2 = os.urandom(2048)
    hash_v2 = hashlib.sha256(doc_v2).hexdigest()
    store.write_chunk(hash_v2, doc_v2)

    prev_manifest = {
        "files": [
            _make_file_entry(f"sheets/budget_{i}.xlsx", hash_v1, hash_v1, len(doc_v1))
            for i in range(8)
        ]
    }
    curr_manifest = {
        "files": [
            _make_file_entry(f"sheets/budget_{i}.xlsx", hash_v2, hash_v2, len(doc_v2))
            for i in range(8)
        ]
    }

    flag = detect_entropy_jumps(prev_manifest, curr_manifest, store)
    assert flag is None
