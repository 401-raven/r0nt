"""Tests for external anchoring subsystem and witness DB migration v2 (SPEC_PHASE3 §1, DECISIONS.md D-14)."""

from __future__ import annotations

import os
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
import pytest

from r0nt.anchor import (
    AnchorBackend,
    AttestationStatus,
    FakeBackend,
    build_anchor_batch,
    compute_anchor_leaf,
    generate_anchor_key,
    run_anchor_batch,
    upgrade_anchors,
    verify_anchors,
)
from r0nt.store import WitnessDB


def _make_dummy_manifest(seq: int, bid: str, m_hash: str) -> dict:
    return {
        "backup_id": bid,
        "sequence_number": seq,
        "manifest_hash": m_hash,
        "prev_manifest_hash": None if seq == 1 else "prev",
        "root_hash": "a" * 64,
        "created_at": "2026-10-18T00:00:00Z",
        "signature": "sig" * 20,
    }


def test_anchor_leaf_determinism():
    key1 = b"K" * 32
    key2 = b"L" * 32
    h = "ab" * 32

    leaf1 = compute_anchor_leaf(key1, h)
    leaf1_again = compute_anchor_leaf(key1, h)
    leaf2 = compute_anchor_leaf(key2, h)

    assert len(leaf1) == 64
    assert leaf1 == leaf1_again
    assert leaf1 != leaf2  # Keyed HMAC prevents correlation without key


def test_build_anchor_batch():
    anchor_key = generate_anchor_key()
    manifests = [
        {"sequence_number": 1, "manifest_hash": "11" * 32},
        {"sequence_number": 2, "manifest_hash": "22" * 32},
        {"sequence_number": 3, "manifest_hash": "33" * 32},
    ]

    root1, members1 = build_anchor_batch(manifests, anchor_key)
    root2, members2 = build_anchor_batch(manifests, anchor_key)

    assert len(root1) == 64
    assert root1 == root2
    assert len(members1) == 3
    assert members1[0]["sequence_number"] == 1
    assert "leaf" in members1[0]
    assert "merkle_path" in members1[0]


def test_witness_db_migration_v1_to_v2(tmp_path: Path):
    db_file = tmp_path / "v1_witness.db"
    mac_key = b"W" * 32

    # 1. Create a pure Schema v1 witness DB manually
    conn = sqlite3.connect(str(db_file))
    conn.executescript("""
        CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        INSERT INTO metadata VALUES ('schema_version', '1');
        CREATE TABLE manifests (
            backup_id TEXT PRIMARY KEY, sequence_number INTEGER NOT NULL UNIQUE,
            manifest_hash TEXT NOT NULL, prev_manifest_hash TEXT, root_hash TEXT NOT NULL,
            created_at TEXT NOT NULL, signature TEXT NOT NULL, row_mac TEXT NOT NULL
        );
        CREATE TABLE verification_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT, run_at TEXT NOT NULL, backup_id TEXT,
            result TEXT NOT NULL, finding_count INTEGER NOT NULL, findings_json TEXT NOT NULL
        );
    """)
    conn.commit()
    conn.close()

    # 2. Open with WitnessDB -> should trigger forward migration to v2
    wdb = WitnessDB(db_file, mac_key)
    cur = wdb.conn.cursor()

    cur.execute("SELECT value FROM metadata WHERE key='schema_version'")
    assert int(cur.fetchone()[0]) >= 2

    # Verify tables 'anchors' and 'anchor_members' now exist
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='anchors'")
    assert cur.fetchone() is not None
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='anchor_members'")
    assert cur.fetchone() is not None

    wdb.close()


def test_anchor_lifecycle_clean(tmp_path: Path):
    db_file = tmp_path / "witness.db"
    mac_key = b"M" * 32
    anchor_key = generate_anchor_key()
    wdb = WitnessDB(db_file, mac_key)
    backend = FakeBackend(confirm_after_ticks=1)

    # 1. Record 2 manifests
    m1 = _make_dummy_manifest(1, "bid1", "11" * 32)
    m2 = _make_dummy_manifest(2, "bid2", "22" * 32)
    wdb.record_manifest(m1)
    wdb.record_manifest(m2)

    assert len(wdb.get_unanchored_manifests()) == 2

    # 2. Run anchor batch
    res = run_anchor_batch(wdb, anchor_key, backend, "fake")
    assert res["status"] == "pending"
    assert res["count"] == 2
    aid = res["anchor_id"]

    # Unanchored list should now be empty
    assert len(wdb.get_unanchored_manifests()) == 0

    # Verification shows anchor_pending info
    findings = verify_anchors(wdb, anchor_key, backend, anchor_grace_hours=24)
    assert any(f["type"] == "anchor_pending" for f in findings)
    assert not any(f["severity"] == "danger" for f in findings)

    # 3. Upgrade anchors (FakeBackend tick)
    backend.confirm_all()
    upgraded = upgrade_anchors(wdb, backend)
    assert len(upgraded) == 1
    assert upgraded[0]["status"] == "confirmed"

    # Verification is now completely clean (0 findings)
    clean_findings = verify_anchors(wdb, anchor_key, backend, anchor_grace_hours=24)
    assert len(clean_findings) == 0

    wdb.close()


def test_anchor_tamper_detection(tmp_path: Path):
    db_file = tmp_path / "tamper_witness.db"
    mac_key = b"M" * 32
    anchor_key = generate_anchor_key()
    wdb = WitnessDB(db_file, mac_key)
    backend = FakeBackend()

    m1 = _make_dummy_manifest(1, "bid1", "aa" * 32)
    wdb.record_manifest(m1)

    res = run_anchor_batch(wdb, anchor_key, backend, "fake")
    aid = res["anchor_id"]
    backend.confirm_all()
    upgrade_anchors(wdb, backend)

    # Tamper 1: Modify batch_root in DB directly without valid MAC
    wdb.conn.execute("UPDATE anchors SET batch_root = ? WHERE id = ?", ("ff" * 32, aid))
    wdb.conn.commit()

    findings = verify_anchors(wdb, anchor_key, backend)
    assert any(f["type"] == "anchor_mismatch" for f in findings)

    # Restore batch_root and update row MAC
    wdb.conn.execute("UPDATE anchors SET batch_root = ? WHERE id = ?", (res["batch_root"], aid))
    anchor_row = wdb.get_anchor(aid)
    new_mac = wdb._compute_anchor_row_mac(
        anchor_row["created_at"], anchor_row["batch_root"], anchor_row["leaf_count"],
        anchor_row["backend"], anchor_row["status"]
    )
    wdb.conn.execute("UPDATE anchors SET row_mac = ? WHERE id = ?", (new_mac, aid))
    wdb.conn.commit()

    # Tamper 2: Corrupt member leaf
    wdb.conn.execute("UPDATE anchor_members SET leaf = ? WHERE anchor_id = ?", ("99" * 32, aid))
    wdb.conn.commit()

    findings2 = verify_anchors(wdb, anchor_key, backend)
    assert any(f["type"] == "anchor_mismatch" for f in findings2)

    wdb.close()


def test_anchor_missing_past_grace_period(tmp_path: Path):
    db_file = tmp_path / "grace_witness.db"
    mac_key = b"M" * 32
    anchor_key = generate_anchor_key()
    wdb = WitnessDB(db_file, mac_key)
    backend = FakeBackend()

    # Create manifest with created_at 30 hours ago
    old_time = (datetime.now(timezone.utc) - timedelta(hours=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
    m = {
        "backup_id": "old_bid",
        "sequence_number": 1,
        "manifest_hash": "77" * 32,
        "prev_manifest_hash": None,
        "root_hash": "88" * 32,
        "created_at": old_time,
        "signature": "sig" * 20,
    }
    wdb.record_manifest(m)

    # Verify with 24h grace period -> should raise anchor_missing warning
    findings = verify_anchors(wdb, anchor_key, backend, anchor_grace_hours=24)
    missing = [f for f in findings if f["type"] == "anchor_missing"]
    assert len(missing) == 1
    assert missing[0]["severity"] == "warning"
    assert missing[0]["sequence_number"] == 1

    wdb.close()


def test_anchor_offline_fallback(tmp_path: Path):
    db_file = tmp_path / "offline_witness.db"
    mac_key = b"M" * 32
    anchor_key = generate_anchor_key()
    wdb = WitnessDB(db_file, mac_key)

    backend = FakeBackend()
    backend.simulate_network_failure = True

    m = _make_dummy_manifest(1, "bid1", "33" * 32)
    wdb.record_manifest(m)

    res = run_anchor_batch(wdb, anchor_key, backend, "fake")
    assert res["status"] == "skipped"
    assert "error" in res

    anchors = wdb.get_all_anchors()
    assert len(anchors) == 1
    assert anchors[0]["status"] == "skipped"

    wdb.close()
