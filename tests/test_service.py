"""Tests for service layer core functions (SPEC_PHASE2 §1)."""

from __future__ import annotations

import threading
from pathlib import Path
import pytest

from r0nt.profile import Profile, SourceConfig
from r0nt.service import (
    BackupResult,
    BackupService,
    KeyService,
    ProfileService,
    RestoreService,
    VerifyResult,
    VerifyService,
)
from r0nt.signing import generate_keypair, save_private_key, save_public_key


def _setup_service_fixture(tmp_path: Path):
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    (src_dir / "file1.txt").write_text("service test content 1")
    (src_dir / "file2.txt").write_text("service test content 2")

    repo_dir = tmp_path / "repo"
    wdb_file = tmp_path / "w.db"
    key_file = tmp_path / "key.pem"
    pub_file = tmp_path / "key.pub.pem"

    priv, pub = generate_keypair()
    save_private_key(priv, key_file)
    save_public_key(pub, pub_file)

    profile = Profile(
        name="test_service",
        sources=[SourceConfig(label="src", path=str(src_dir))],
        repo=str(repo_dir),
        witness_db=str(wdb_file),
        key_path=str(key_file),
        pubkey_path=str(pub_file),
    )

    return profile, src_dir, repo_dir, wdb_file, key_file, pub_file


def test_backup_and_verify_service_flow(tmp_path: Path):
    profile, src_dir, repo_dir, wdb_file, key_file, pub_file = _setup_service_fixture(tmp_path)

    backup_service = BackupService()
    verify_service = VerifyService()

    # Progress tracker
    progress_updates = []
    def on_progress(current_file, files_done, bytes_done):
        progress_updates.append((current_file, files_done, bytes_done))

    # Run backup
    b_result = backup_service.run_backup(profile, progress_callback=on_progress)
    assert isinstance(b_result, BackupResult)
    assert b_result.files_backed_up == 2
    assert len(progress_updates) == 2
    assert b_result.backup_id is not None
    assert b_result.sequence_number == 1

    # Run verify
    v_result = verify_service.run_verify(profile, mode="full")
    assert isinstance(v_result, VerifyResult)
    assert v_result.is_clean is True
    assert v_result.findings == []
    assert v_result.snapshots_checked == 1


def test_backup_cancellation(tmp_path: Path):
    profile, src_dir, repo_dir, wdb_file, key_file, pub_file = _setup_service_fixture(tmp_path)
    backup_service = BackupService()

    cancel_event = threading.Event()
    cancel_event.set()  # Cancel immediately

    b_result = backup_service.run_backup(profile, cancel_event=cancel_event)
    assert b_result.cancelled is True

    # Ensure no manifest was written
    manifests_dir = repo_dir / "manifests"
    if manifests_dir.exists():
        assert len(list(manifests_dir.glob("*.json"))) == 0


def test_key_service(tmp_path: Path):
    key_service = KeyService()
    priv_file = tmp_path / "generated.pem"
    pub_file = tmp_path / "generated.pub.pem"

    key_info = key_service.generate_keypair_files(priv_file, pub_file, passphrase="test-passphrase")
    assert key_info.encrypted is True
    assert key_info.key_id is not None
    assert priv_file.exists()
    assert pub_file.exists()

    info = key_service.get_key_info(priv_file, pub_file)
    assert info.encrypted is True
    assert info.key_id == key_info.key_id


def test_anchor_service_flow(tmp_path: Path):
    from r0nt.service import AnchorService
    profile, src_dir, repo_dir, wdb_file, key_file, pub_file = _setup_service_fixture(tmp_path)
    backup_service = BackupService()
    anchor_service = AnchorService()

    # 1. Backup snapshot
    backup_service.run_backup(profile)

    # 2. Check anchor status
    status = anchor_service.get_status(profile)
    assert status["unanchored_manifests"] == 1
    assert status["total_anchors"] == 0

    # 3. Run anchor batch
    res = anchor_service.run_anchor(profile, backend_name="fake")
    assert res["status"] == "pending"
    assert res["count"] == 1

    # 4. Upgrade anchors
    upgraded = anchor_service.upgrade_anchors(profile, backend_name="fake")
    assert len(upgraded) == 1
    assert upgraded[0]["status"] == "confirmed"

    # 5. Verify anchors
    findings = anchor_service.verify_anchors(profile, backend_name="fake")
    assert len(findings) == 0


def test_restore_test_service_flow(tmp_path: Path):
    from r0nt.service import RestoreTestService
    profile, src_dir, repo_dir, wdb_file, key_file, pub_file = _setup_service_fixture(tmp_path)
    backup_service = BackupService()
    rt_service = RestoreTestService()

    backup_service.run_backup(profile)

    rt_res = rt_service.run_test(profile, sample_percent=100.0)
    assert rt_res.status == "passed"
    assert rt_res.failed_count == 0
    assert rt_res.passed_count == 2

