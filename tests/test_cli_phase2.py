"""Tests for Phase 2 CLI commands, subcommands, and exit codes (SPEC_PHASE2 §3)."""

from __future__ import annotations

import json
from pathlib import Path
import pytest

from r0nt.cli import main
from r0nt.profile import Profile, ProfileManager, SourceConfig
from r0nt.signing import generate_keypair, save_private_key, save_public_key


def _setup_cli_profile(tmp_path: Path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "test.txt").write_text("cli test content")

    repo = tmp_path / "repo"
    wdb = tmp_path / "witness.db"
    key = tmp_path / "key.pem"
    pubkey = tmp_path / "key.pub.pem"

    priv, pub = generate_keypair()
    save_private_key(priv, key)
    save_public_key(pub, pubkey)

    cfg_file = tmp_path / "profiles.toml"
    pm = ProfileManager(cfg_file)
    p = Profile(
        name="testcli",
        sources=[SourceConfig(label="src", path=str(src))],
        repo=str(repo),
        witness_db=str(wdb),
        key_path=str(key),
        pubkey_path=str(pubkey),
    )
    pm.save_profile(p)
    return p, cfg_file, src, repo, wdb, key, pubkey


def test_cli_profile_list_json(tmp_path: Path):
    p, cfg_file, *_ = _setup_cli_profile(tmp_path)
    exit_code = main(["--config", str(cfg_file), "profile", "list", "--json"])
    assert exit_code == 0


def test_cli_backup_and_verify(tmp_path: Path):
    p, cfg_file, src, repo, wdb, key, pubkey = _setup_cli_profile(tmp_path)

    # 1. Backup via profile
    code = main(["--config", str(cfg_file), "backup", "--profile", "testcli"])
    assert code == 0

    # 2. Verify via profile (clean -> exit 0)
    code = main(["--config", str(cfg_file), "verify", "--profile", "testcli", "--mode", "quick"])
    assert code == 0

    # 3. List snapshots via profile
    code = main(["--config", str(cfg_file), "list", "--profile", "testcli", "--json"])
    assert code == 0

    # 4. Tamper chunk -> full verify should exit 1
    chunks = list((repo / "chunks").glob("*/*"))
    assert len(chunks) > 0
    cfile = chunks[0]
    data = bytearray(cfile.read_bytes())
    data[0] ^= 0xFF
    cfile.write_bytes(bytes(data))

    code = main(["--config", str(cfg_file), "verify", "--profile", "testcli", "--mode", "full"])
    assert code == 1


def test_cli_restore_command(tmp_path: Path):
    p, cfg_file, src, repo, wdb, key, pubkey = _setup_cli_profile(tmp_path)

    main(["--config", str(cfg_file), "backup", "--profile", "testcli"])
    target = tmp_path / "restored_dir"

    code = main(["--config", str(cfg_file), "restore", "1", "--profile", "testcli", "--target", str(target)])
    assert code == 0
    assert (target / "src" / "test.txt").read_text() == "cli test content"


def test_cli_schedule_help(tmp_path: Path, capsys):
    p, cfg_file, *_ = _setup_cli_profile(tmp_path)
    code = main(["--config", str(cfg_file), "schedule-help", "--profile", "testcli"])
    assert code == 0
    captured = capsys.readouterr()
    assert "schtasks" in captured.out or "cron" in captured.out
    assert "anchor" in captured.out
    assert "restore-test" in captured.out


def test_cli_anchor_lifecycle(tmp_path: Path, capsys):
    p, cfg_file, src, repo, wdb, key, pubkey = _setup_cli_profile(tmp_path)

    # 1. Backup snapshot
    main(["--config", str(cfg_file), "backup", "--profile", "testcli"])
    capsys.readouterr()  # Flush stdout from backup

    # 2. Anchor status
    code = main(["--config", str(cfg_file), "anchor", "status", "--profile", "testcli", "--json"])
    assert code == 0
    captured = capsys.readouterr()
    stat = json.loads(captured.out)
    assert stat["unanchored_manifests"] == 1

    # 3. Anchor run
    code = main(["--config", str(cfg_file), "anchor", "run", "--profile", "testcli", "--backend", "fake", "--json"])
    assert code == 0
    captured = capsys.readouterr()
    run_res = json.loads(captured.out)
    assert run_res["status"] == "pending"
    assert run_res["count"] == 1

    # 4. Anchor upgrade
    code = main(["--config", str(cfg_file), "anchor", "upgrade", "--profile", "testcli", "--backend", "fake", "--json"])
    assert code == 0
    captured = capsys.readouterr()
    upgraded = json.loads(captured.out)
    assert len(upgraded) == 1
    assert upgraded[0]["status"] == "confirmed"

    # 5. Anchor verify
    code = main(["--config", str(cfg_file), "anchor", "verify", "--profile", "testcli", "--backend", "fake", "--json"])
    assert code == 0
    captured = capsys.readouterr()
    findings = json.loads(captured.out)
    assert findings == []


def test_cli_restore_test(tmp_path: Path, capsys):
    p, cfg_file, src, repo, wdb, key, pubkey = _setup_cli_profile(tmp_path)

    main(["--config", str(cfg_file), "backup", "--profile", "testcli"])
    capsys.readouterr()

    code = main(["--config", str(cfg_file), "restore-test", "--profile", "testcli", "--json"])
    assert code == 0
    captured = capsys.readouterr()
    res = json.loads(captured.out)
    assert res["status"] == "passed"
    assert res["sample_count"] == 1
    assert res["failed_count"] == 0


def test_cli_verify_risk_flags_reported(tmp_path: Path, capsys):
    p, cfg_file, src, repo, wdb, key, pubkey = _setup_cli_profile(tmp_path)

    # Backup 1: initial text file
    main(["--config", str(cfg_file), "backup", "--profile", "testcli"])

    # Simulate widespread ransomware mass rename to .locked for Backup 2
    for i in range(15):
        (src / f"file_{i}.txt").write_text(f"content {i}")
    main(["--config", str(cfg_file), "backup", "--profile", "testcli"])

    for i in range(15):
        (src / f"file_{i}.txt").unlink()
        (src / f"file_{i}.locked").write_text(f"encrypted {i}")
    main(["--config", str(cfg_file), "backup", "--profile", "testcli"])
    capsys.readouterr()

    # Verify JSON should include risk_flags
    code = main(["--config", str(cfg_file), "verify", "--profile", "testcli", "--json"])
    assert code == 0  # Integrity findings are 0, risk flags are reported separately
    captured = capsys.readouterr()
    res = json.loads(captured.out)
    assert "risk_flags" in res
    assert len(res["risk_flags"]) > 0
    kinds = [rf["kind"] for rf in res["risk_flags"]]
    assert "extension_change" in kinds or "change_spike" in kinds


def test_cli_no_args_prints_help(capsys):
    code = main([])
    assert code == 0
    captured = capsys.readouterr()
    assert "usage: r0nt" in captured.out
    assert "Tamper-evident backup verification system" in captured.out


def test_cli_unknown_command():
    code = main(["nonexistent-command"])
    assert code == 2


def test_cli_profile_use_and_default_resolution(tmp_path: Path, capsys):
    p, cfg_file, *_ = _setup_cli_profile(tmp_path)

    # 1. Set default profile via profile use
    code = main(["--config", str(cfg_file), "profile", "use", "testcli", "--json"])
    assert code == 0
    captured = capsys.readouterr()
    res = json.loads(captured.out)
    assert res["default_profile"] == "testcli"

    # 2. Run list without --profile (resolves to default)
    code = main(["--config", str(cfg_file), "list", "--json"])
    assert code == 0


def test_cli_status_json_and_strict(tmp_path: Path, capsys):
    p, cfg_file, src, repo, wdb, key, pubkey = _setup_cli_profile(tmp_path)

    # Backup once so repo is initialized
    main(["--config", str(cfg_file), "backup", "--profile", "testcli"])
    capsys.readouterr()

    # Status in JSON format
    code = main(["--config", str(cfg_file), "status", "--profile", "testcli", "--json"])
    assert code == 0
    captured = capsys.readouterr()
    status_data = json.loads(captured.out)
    assert status_data["profile"] == "testcli"
    assert status_data["snapshot_count"] == 1
    assert status_data["chain_health"] == "healthy"
    assert "warnings" in status_data

    # Since repo & wdb are both under tmp_path (same drive), strict mode should exit 1 (EXIT_FINDINGS)
    code_strict = main(["--config", str(cfg_file), "status", "--profile", "testcli", "--strict"])
    assert code_strict == 1


