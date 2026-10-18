"""Command-line interface for r0nt (SPEC §7 & SPEC_PHASE2 §3).

Provides CLI commands backed entirely by the service layer:
  - backup, verify, restore, list, show, diff
  - profile (list, show, add, remove)
  - key (info, export-public)
  - history, report, schedule-help
"""

from __future__ import annotations

import argparse
import getpass
import json
import logging
from logging.handlers import RotatingFileHandler
import os
import sys
from pathlib import Path
from typing import Any

import platformdirs

from r0nt.diff import diff_snapshots, get_snapshot_detail, list_snapshots
from r0nt.profile import Profile, ProfileManager, SourceConfig
from r0nt.service import (
    AnchorService,
    BackupService,
    HistoryService,
    KeyService,
    ProfileService,
    RestoreService,
    RestoreTestService,
    StatusService,
    VerifyService,
)
from r0nt.signing import generate_keypair, is_private_key_encrypted, save_private_key, save_public_key

# Exit codes per SPEC_PHASE2 §3
EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_USAGE_ERROR = 2
EXIT_OPERATIONAL_FAILURE = 3
EXIT_CANCELLED = 130


def _setup_logging() -> None:
    """Setup rotating file logger in the user log directory."""
    try:
        log_dir = Path(platformdirs.user_log_dir("r0nt"))
        log_dir.mkdir(parents=True, exist_ok=True)
        log_file = log_dir / "r0nt.log"

        handler = RotatingFileHandler(
            log_file,
            maxBytes=5 * 1024 * 1024,
            backupCount=3,
            encoding='utf-8',
        )
        formatter = logging.Formatter(
            '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
        )
        handler.setFormatter(formatter)

        logger = logging.getLogger("r0nt")
        logger.setLevel(logging.INFO)
        if not logger.handlers:
            logger.addHandler(handler)
    except Exception:
        pass


def _resolve_profile(args: argparse.Namespace, pm: ProfileManager) -> Profile:
    """Resolve Profile from --profile, default_profile, or ephemeral direct flags."""
    profile_name = getattr(args, "profile", None)
    if not profile_name:
        settings = pm.get_settings()
        profile_name = settings.get("default_profile")

    if profile_name:
        p = pm.get_profile(profile_name)
        if p is None:
            raise ValueError(f"Profile '{profile_name}' not found.")
        return p

    # Fallback to direct flags
    if not hasattr(args, "repo") or not args.repo:
        raise ValueError("Either --profile, a configured default profile, or direct parameters (--repo, etc.) must be specified.")

    source_path = getattr(args, "source", None)
    sources = [SourceConfig(label="source", path=source_path)] if source_path else []

    return Profile(
        name="ephemeral",
        sources=sources or [SourceConfig(label="source", path=".")],
        repo=args.repo,
        witness_db=getattr(args, "witness_db", "") or "",
        key_path=getattr(args, "key", "") or "",
        pubkey_path=getattr(args, "pubkey", "") or "",
        chunk_size=getattr(args, "chunk_size", 1024 * 1024),
    )


def _get_passphrase(key_path: Path) -> str | None:
    """Prompt for passphrase if key is encrypted, or check R0NT_KEY_PASSPHRASE env var."""
    if not key_path.exists() or not is_private_key_encrypted(key_path):
        return None

    env_pw = os.environ.get("R0NT_KEY_PASSPHRASE")
    if env_pw:
        return env_pw

    if sys.stdin.isatty():
        return getpass.getpass(f"Enter passphrase for key '{key_path}': ")

    raise ValueError(f"Passphrase required for '{key_path}' but terminal is non-interactive. Set R0NT_KEY_PASSPHRASE.")


# =========================================================================
# Subcommand Handlers
# =========================================================================

def cmd_init(args: argparse.Namespace, pm: ProfileManager) -> int:
    priv_path = Path(args.key).resolve()
    pub_path = Path(args.pubkey).resolve()

    if priv_path.exists() and not args.force:
        print(f"Error: Private key already exists: {priv_path}. Use --force to overwrite.", file=sys.stderr)
        return EXIT_USAGE_ERROR

    passphrase = None
    if getattr(args, "encrypt", False):
        if sys.stdin.isatty():
            p1 = getpass.getpass("Enter passphrase to encrypt private key: ")
            p2 = getpass.getpass("Confirm passphrase: ")
            if p1 != p2:
                print("Error: Passphrases do not match.", file=sys.stderr)
                return EXIT_USAGE_ERROR
            passphrase = p1
        else:
            passphrase = os.environ.get("R0NT_KEY_PASSPHRASE")

    ks = KeyService()
    info = ks.generate_keypair_files(priv_path, pub_path, passphrase=passphrase, force=args.force)

    if args.json:
        print(json.dumps({
            "key_id": info.key_id,
            "private_key": info.private_key_path,
            "public_key": info.public_key_path,
            "encrypted": info.encrypted,
        }, indent=2))
    else:
        print("=" * 60)
        print("r0nt Keypair Initialized")
        print("=" * 60)
        print(f"Key ID:      {info.key_id}")
        print(f"Private Key: {info.private_key_path}")
        print(f"Public Key:  {info.public_key_path}")
        print(f"Encrypted:   {'Yes' if info.encrypted else 'No (Warning: unencrypted)'}")
        print("=" * 60)

    return EXIT_CLEAN


def cmd_backup(args: argparse.Namespace, pm: ProfileManager) -> int:
    profile = _resolve_profile(args, pm)
    passphrase = _get_passphrase(Path(profile.key_path))

    bs = BackupService()
    result = bs.run_backup(profile, passphrase=passphrase, dry_run=args.dry_run)

    if result.cancelled:
        return EXIT_CANCELLED

    for w in result.warnings:
        print(f"Notice: {w}", file=sys.stderr)

    if args.json:
        print(json.dumps({
            "backup_id": result.backup_id,
            "sequence_number": result.sequence_number,
            "created_at": result.created_at,
            "files": result.files_backed_up,
            "chunks": result.total_chunks,
            "size": result.total_bytes,
            "root_hash": result.root_hash,
            "manifest_hash": result.manifest_hash,
        }, indent=2))
    else:
        print("-" * 60)
        print("Backup Completed Successfully")
        print("-" * 60)
        print(f"Backup ID:    {result.backup_id}")
        print(f"Sequence:     {result.sequence_number}")
        print(f"Files:        {result.files_backed_up} (Skipped: {result.skipped_files})")
        print(f"Total Chunks: {result.total_chunks} (New: {result.new_chunks}, Dedup: {result.dedup_chunks})")
        print(f"Total Size:   {result.total_bytes} bytes")
        print(f"Root Hash:    {result.root_hash}")
        print("-" * 60)

    return EXIT_CLEAN


def cmd_verify(args: argparse.Namespace, pm: ProfileManager) -> int:
    profile = _resolve_profile(args, pm)
    vs = VerifyService()

    mode = getattr(args, "mode", "full")
    percent = getattr(args, "percent", 10.0)

    res = vs.run_verify(profile, mode=mode, sample_percent=percent)

    for w in res.warnings:
        print(f"Notice: {w}", file=sys.stderr)

    findings_dicts = [f._asdict() for f in res.findings]

    if args.json:
        payload = {
            "result": "clean" if res.is_clean else "findings",
            "mode": mode,
            "finding_count": res.finding_count,
            "findings": findings_dicts,
            "stats": res.stats,
            "risk_flags": [
                {
                    "kind": rf.kind,
                    "severity": rf.severity,
                    "score": rf.score,
                    "evidence": rf.evidence,
                    "description": rf.description,
                }
                for rf in res.risk_flags
            ],
        }
        print(json.dumps(payload, indent=2))
    else:
        if res.is_clean:
            print("=" * 60)
            print(f"[CLEAN] Verification Successful (Mode: {mode.upper()})")
            print("=" * 60)
            print("No integrity violations or tampering detected.")
            if mode == "sample":
                print(f"Checked random sample of {res.stats.get('sampled_chunks', 0)} chunks.")
                print("Caution: Sampling can miss localized corruption.")
            print("=" * 60)
        else:
            print("=" * 60, file=sys.stderr)
            print(f"[TAMPERING DETECTED] Found {res.finding_count} integrity finding(s):", file=sys.stderr)
            print("=" * 60, file=sys.stderr)
            for i, f in enumerate(res.findings, 1):
                print(f"  {i}. [{f.type.upper()}]: {f.message}", file=sys.stderr)
            print("=" * 60, file=sys.stderr)

        if res.risk_flags:
            print("-" * 60)
            print(f"Heuristic Risk Indicators ({len(res.risk_flags)}):")
            for rf in res.risk_flags:
                print(f"  * [{rf.severity.upper()}] {rf.kind}: {rf.description}")
            print("-" * 60)

    return EXIT_CLEAN if res.is_clean else EXIT_FINDINGS


def cmd_restore(args: argparse.Namespace, pm: ProfileManager) -> int:
    profile = _resolve_profile(args, pm)
    rs = RestoreService()

    target = Path(args.target).resolve()
    paths = args.path if getattr(args, "path", None) else None

    result = rs.run_restore(
        profile=profile,
        snapshot_id=args.snapshot,
        target_dir=target,
        paths=paths,
        allow_nonempty=args.allow_nonempty,
        overwrite=args.overwrite,
    )

    if args.json:
        print(json.dumps({
            "backup_id": result.backup_id,
            "target": result.target_dir,
            "files_restored": result.files_restored,
            "bytes_restored": result.bytes_restored,
        }, indent=2))
    else:
        print("-" * 60)
        print("Restore Completed Successfully")
        print("-" * 60)
        print(f"Snapshot:       {result.backup_id}")
        print(f"Target:         {result.target_dir}")
        print(f"Files Restored: {result.files_restored}")
        print(f"Bytes Restored: {result.bytes_restored}")
        print("-" * 60)

    return EXIT_CLEAN


def cmd_list(args: argparse.Namespace, pm: ProfileManager) -> int:
    profile = _resolve_profile(args, pm)
    pub = Path(profile.pubkey_path)
    from r0nt.signing import load_public_key
    public_key = load_public_key(pub)

    summaries = list_snapshots(Path(profile.repo), public_key)

    if args.json:
        print(json.dumps([s.__dict__ for s in summaries], indent=2))
    else:
        print(f"{'Seq':<5} {'Backup ID':<38} {'Date':<22} {'Files':<8} {'Size':<12} {'Signature'}")
        print("-" * 95)
        for s in summaries:
            sig_str = "Valid" if s.signature_valid else "INVALID"
            print(f"{s.sequence_number:<5} {s.backup_id:<38} {s.created_at:<22} {s.file_count:<8} {s.total_size:<12} {sig_str}")

    return EXIT_CLEAN


def cmd_show(args: argparse.Namespace, pm: ProfileManager) -> int:
    profile = _resolve_profile(args, pm)
    from r0nt.signing import load_public_key
    public_key = load_public_key(Path(profile.pubkey_path))

    detail = get_snapshot_detail(Path(profile.repo), args.snapshot, public_key, prefix=args.path)

    if args.json:
        print(json.dumps({
            "summary": detail.summary.__dict__,
            "chunk_size": detail.chunk_size,
            "key_id": detail.key_id,
            "prev_manifest_hash": detail.prev_manifest_hash,
            "files": detail.files,
            "skipped_files": detail.skipped_files,
        }, indent=2))
    else:
        print("=" * 60)
        print(f"Snapshot {detail.summary.sequence_number}: {detail.summary.backup_id}")
        print("=" * 60)
        print(f"Created At:  {detail.summary.created_at}")
        print(f"Root Hash:   {detail.summary.root_hash}")
        print(f"Key ID:      {detail.key_id}")
        print(f"Files Count: {len(detail.files)}")
        print("-" * 60)
        for f in detail.files[:50]:
            print(f"  {f['path']} ({f['size']} bytes)")
        if len(detail.files) > 50:
            print(f"  ... and {len(detail.files) - 50} more files")

    return EXIT_CLEAN


def cmd_diff(args: argparse.Namespace, pm: ProfileManager) -> int:
    profile = _resolve_profile(args, pm)
    diff = diff_snapshots(Path(profile.repo), args.snapshotA, args.snapshotB)

    if args.json:
        print(json.dumps(diff.__dict__, indent=2))
    else:
        print(f"Diff: Snapshot {diff.snapshot_a} -> {diff.snapshot_b}")
        print("-" * 60)
        print(f"Added files ({len(diff.added_files)}):")
        for f in diff.added_files:
            print(f"  + {f}")
        print(f"Removed files ({len(diff.removed_files)}):")
        for f in diff.removed_files:
            print(f"  - {f}")
        print(f"Modified files ({len(diff.modified_files)}):")
        for f in diff.modified_files:
            print(f"  * {f}")

    return EXIT_CLEAN


def cmd_profile(args: argparse.Namespace, pm: ProfileManager) -> int:
    sub = args.profile_action
    if sub == "list":
        profiles = pm.list_profiles()
        if args.json:
            print(json.dumps(profiles, indent=2))
        else:
            for name in profiles:
                print(name)
        return EXIT_CLEAN

    if sub == "show":
        p = pm.get_profile(args.name)
        if p is None:
            print(f"Error: Profile '{args.name}' not found.", file=sys.stderr)
            return EXIT_USAGE_ERROR
        p_dict = {
            "name": p.name,
            "sources": [{"label": s.label, "path": s.path} for s in p.sources],
            "repo": p.repo,
            "witness_db": p.witness_db,
            "key_path": p.key_path,
            "pubkey_path": p.pubkey_path,
            "chunk_size": p.chunk_size,
            "exclude": p.exclude,
        }
        if args.json:
            print(json.dumps(p_dict, indent=2))
        else:
            for k, v in p_dict.items():
                print(f"{k}: {v}")
        return EXIT_CLEAN

    if sub == "remove":
        ok = pm.delete_profile(args.name)
        if not ok:
            print(f"Error: Profile '{args.name}' not found.", file=sys.stderr)
            return EXIT_USAGE_ERROR
        print(f"Profile '{args.name}' removed.")
        return EXIT_CLEAN

    if sub == "use":
        p = pm.get_profile(args.name)
        if p is None:
            print(f"Error: Profile '{args.name}' not found.", file=sys.stderr)
            return EXIT_USAGE_ERROR
        pm.update_settings(default_profile=args.name)
        if getattr(args, "json", False):
            print(json.dumps({"default_profile": args.name}))
        else:
            print(f"Default profile set to '{args.name}'.")
        return EXIT_CLEAN

    return EXIT_USAGE_ERROR


def cmd_key(args: argparse.Namespace, pm: ProfileManager) -> int:
    sub = args.key_action
    ks = KeyService()

    if sub == "info":
        profile = _resolve_profile(args, pm)
        info = ks.get_key_info(Path(profile.key_path), Path(profile.pubkey_path))
        if args.json:
            print(json.dumps(info.__dict__, indent=2))
        else:
            print(f"Key ID:      {info.key_id}")
            print(f"Private Key: {info.private_key_path}")
            print(f"Public Key:  {info.public_key_path}")
            print(f"Encrypted:   {info.encrypted}")
            for w in info.warnings:
                print(f"Notice: {w}")
        return EXIT_CLEAN

    if sub == "export-public":
        profile = _resolve_profile(args, pm)
        ks.export_public_key(Path(profile.pubkey_path), Path(args.out_file))
        print(f"Public key exported to: {args.out_file}")
        return EXIT_CLEAN

    return EXIT_USAGE_ERROR


def cmd_history(args: argparse.Namespace, pm: ProfileManager) -> int:
    profile = _resolve_profile(args, pm)
    hs = HistoryService()
    items = hs.get_history(profile)

    if args.json:
        print(json.dumps([it.__dict__ for it in items], indent=2))
    else:
        print(f"{'ID':<6} {'Run At':<22} {'Backup ID':<38} {'Result':<10} {'Findings'}")
        print("-" * 85)
        for it in items:
            bid = it.backup_id or "N/A"
            print(f"{it.id:<6} {it.run_at:<22} {bid:<38} {it.result:<10} {it.finding_count}")

    return EXIT_CLEAN


def cmd_schedule_help(args: argparse.Namespace, pm: ProfileManager) -> int:
    profile = _resolve_profile(args, pm)
    p_name = profile.name

    schtasks_backup = f'schtasks /create /tn "r0nt_backup_{p_name}" /tr "r0nt backup --profile {p_name}" /sc daily /st 02:00'
    schtasks_anchor = f'schtasks /create /tn "r0nt_anchor_{p_name}" /tr "r0nt anchor run --profile {p_name}" /sc daily /st 03:00'
    schtasks_verify = f'schtasks /create /tn "r0nt_verify_{p_name}" /tr "r0nt verify --profile {p_name} --mode full" /sc weekly /d SUN /st 04:00'
    schtasks_restore_test = f'schtasks /create /tn "r0nt_restoretest_{p_name}" /tr "r0nt restore-test --profile {p_name}" /sc weekly /d SUN /st 05:00'

    cron_backup = f'0 2 * * * r0nt backup --profile {p_name} >> /var/log/r0nt_backup.log 2>&1'
    cron_anchor = f'0 3 * * * r0nt anchor run --profile {p_name} >> /var/log/r0nt_anchor.log 2>&1'
    cron_verify = f'0 4 * * 0 r0nt verify --profile {p_name} --mode full >> /var/log/r0nt_verify.log 2>&1'
    cron_restore_test = f'0 5 * * 0 r0nt restore-test --profile {p_name} >> /var/log/r0nt_restoretest.log 2>&1'

    if args.json:
        print(json.dumps({
            "windows_task_scheduler": {
                "backup": schtasks_backup,
                "anchor": schtasks_anchor,
                "verify": schtasks_verify,
                "restore_test": schtasks_restore_test,
            },
            "cron": {
                "backup": cron_backup,
                "anchor": cron_anchor,
                "verify": cron_verify,
                "restore_test": cron_restore_test,
            }
        }, indent=2))
    else:
        print("=" * 60)
        print("Ready-to-Paste Scheduled Commands")
        print("=" * 60)
        print("\n--- Windows Task Scheduler (Run in Administrator Command Prompt) ---")
        print(f"Backup (Daily at 02:00):\n  {schtasks_backup}\n")
        print(f"Anchor (Daily at 03:00):\n  {schtasks_anchor}\n")
        print(f"Verify (Weekly on Sunday at 04:00):\n  {schtasks_verify}\n")
        print(f"Restore-Test (Weekly on Sunday at 05:00):\n  {schtasks_restore_test}\n")
        print("--- Linux / macOS (cron entries) ---")
        print(f"Backup (Daily at 02:00):\n  {cron_backup}\n")
        print(f"Anchor (Daily at 03:00):\n  {cron_anchor}\n")
        print(f"Verify (Weekly on Sunday at 04:00):\n  {cron_verify}\n")
        print(f"Restore-Test (Weekly on Sunday at 05:00):\n  {cron_restore_test}\n")
        print("=" * 60)

    return EXIT_CLEAN


def cmd_anchor(args: argparse.Namespace, pm: ProfileManager) -> int:
    profile = _resolve_profile(args, pm)
    asvc = AnchorService()
    sub = args.anchor_action
    backend_name = getattr(args, "backend", "fake")

    if sub == "run":
        res = asvc.run_anchor(profile, backend_name=backend_name)
        if args.json:
            print(json.dumps(res, indent=2))
        else:
            status = res.get("status", "unknown")
            if status == "pending":
                print(f"[ANCHOR BATCH SUBMITTED] Batch root: {res.get('batch_root')} ({res.get('count')} manifests)")
            elif status == "skipped":
                print(f"[ANCHOR SKIPPED] {res.get('error', 'Network failure - batch saved as skipped')}", file=sys.stderr)
            elif status == "empty":
                print(res.get("message", "No unanchored manifests found."))
            else:
                print(f"Anchor run: {res}")
        return EXIT_CLEAN

    elif sub == "upgrade":
        upgraded = asvc.upgrade_anchors(profile, backend_name=backend_name)
        if args.json:
            print(json.dumps(upgraded, indent=2))
        else:
            print(f"Upgraded {len(upgraded)} anchor batch(es) to confirmed.")
            for u in upgraded:
                print(f"  * Anchor #{u['anchor_id']} (Root: {u['batch_root'][:16]}...) confirmed at {u['confirmed_at']}")
        return EXIT_CLEAN

    elif sub == "status":
        stat = asvc.get_status(profile)
        if args.json:
            print(json.dumps(stat, indent=2))
        else:
            print("=" * 50)
            print("External Anchoring Status")
            print("=" * 50)
            print(f"Total Batches:        {stat['total_anchors']}")
            print(f"Pending Batches:      {stat['pending_count']}")
            print(f"Confirmed Batches:    {stat['confirmed_count']}")
            print(f"Unanchored Manifests: {stat['unanchored_manifests']}")
            if stat.get("latest_anchor"):
                la = stat["latest_anchor"]
                print(f"Latest Batch ID:      {la['id']} (Status: {la['status']}, Created: {la['created_at']})")
            print("=" * 50)
        return EXIT_CLEAN

    elif sub == "verify":
        grace_hours = getattr(args, "grace_hours", 24)
        findings = asvc.verify_anchors(profile, backend_name=backend_name, grace_hours=grace_hours)
        if args.json:
            print(json.dumps(findings, indent=2))
        else:
            if not findings:
                print("=" * 50)
                print("[ANCHOR VERIFICATION CLEAN] All batches and proofs valid.")
                print("=" * 50)
            else:
                print("=" * 50, file=sys.stderr)
                print(f"Anchor verification findings ({len(findings)}):", file=sys.stderr)
                for f in findings:
                    print(f"  * [{f.get('severity', 'info').upper()}] {f.get('type')}: {f.get('message')}", file=sys.stderr)
                print("=" * 50, file=sys.stderr)

        has_danger = any(f.get("severity") in ("danger", "warning") for f in findings)
        return EXIT_FINDINGS if has_danger else EXIT_CLEAN

    return EXIT_USAGE_ERROR


def cmd_restore_test(args: argparse.Namespace, pm: ProfileManager) -> int:
    profile = _resolve_profile(args, pm)
    rts = RestoreTestService()

    snapshot = getattr(args, "snapshot", None)
    sample = getattr(args, "sample", None)
    percent = getattr(args, "percent", None)
    workdir = Path(args.workdir).resolve() if getattr(args, "workdir", None) else None

    res = rts.run_test(
        profile=profile,
        snapshot_id=snapshot,
        sample_count=sample,
        sample_percent=percent,
        workdir=workdir,
    )

    if args.json:
        print(json.dumps({
            "status": res.status,
            "exit_code": res.exit_code,
            "sample_count": res.sample_count,
            "passed_count": res.passed_count,
            "failed_count": res.failed_count,
            "duration_seconds": res.duration_seconds,
            "failures": [
                {"path": f.path, "stage": f.stage, "reason": f.reason}
                for f in res.failures
            ],
        }, indent=2))
    else:
        print("=" * 60)
        print(f"Restore Test Summary ({res.status.upper()})")
        print("=" * 60)
        print(f"Snapshot:     {res.backup_id}")
        print(f"Files Tested: {res.sample_count} (Passed: {res.passed_count}, Failed: {res.failed_count})")
        print(f"Duration:     {res.duration_seconds}s")
        if res.failures:
            print("-" * 60, file=sys.stderr)
            print("Failures encountered:", file=sys.stderr)
            for f in res.failures:
                print(f"  * [{f.stage}] {f.path}: {f.reason}", file=sys.stderr)
            print("-" * 60, file=sys.stderr)
        print("=" * 60)

    return res.exit_code


def cmd_status(args: argparse.Namespace, pm: ProfileManager) -> int:
    profile = _resolve_profile(args, pm)
    svc = StatusService()
    res = svc.get_status(profile)

    if getattr(args, "json", False):
        out = {
            "profile": res.profile_name,
            "snapshot_count": res.snapshot_count,
            "last_backup_time": res.last_backup_time,
            "last_backup_relative": res.last_backup_relative,
            "chain_health": res.chain_health,
            "last_verify": res.last_verify,
            "last_anchor": res.last_anchor,
            "last_restore_test": res.last_restore_test,
            "warnings": res.warnings,
            "clean": not res.has_warnings,
        }
        print(json.dumps(out, indent=2))
    else:
        print("=" * 60)
        print(f"r0nt Health Status -- Profile: {res.profile_name}")
        print("=" * 60)
        print(f"Snapshots:       {res.snapshot_count}")
        last_bk_str = f"{res.last_backup_time} ({res.last_backup_relative})" if res.last_backup_time else "None"
        print(f"Last Backup:     {last_bk_str}")
        print(f"Chain Health:    {res.chain_health.upper()}")

        if res.last_verify:
            lv = res.last_verify
            print(f"Last Verify:     {lv['result']} [mode: {lv['mode']}] at {lv['timestamp']} ({lv['relative']})")
        else:
            print("Last Verify:     Never verified")

        if res.last_anchor:
            la = res.last_anchor
            print(f"Anchors:         Total: {la['total_anchors']}, Pending: {la['pending_count']}, Confirmed: {la['confirmed_count']}, Unanchored: {la['unanchored_manifests']}")
        else:
            print("Anchors:         None")

        if res.last_restore_test:
            lrt = res.last_restore_test
            print(f"Restore Test:    {lrt['status'].upper()} (sample: {lrt['sample_count']}, failed: {lrt['failed_count']}) at {lrt['run_at']} ({lrt['relative']})")
        else:
            print("Restore Test:    None")

        if res.has_warnings:
            print("-" * 60, file=sys.stderr)
            print(f"Warnings ({len(res.warnings)}):", file=sys.stderr)
            for w in res.warnings:
                print(f"  * [WARNING] {w}", file=sys.stderr)
            print("=" * 60)
        else:
            print("-" * 60)
            print("[HEALTH CLEAN] No warnings detected.")
            print("=" * 60)

    if getattr(args, "strict", False) and res.has_warnings:
        return EXIT_FINDINGS
    return EXIT_CLEAN



# =========================================================================
# Parser Construction
# =========================================================================

def build_parser() -> argparse.ArgumentParser:
    base_parser = argparse.ArgumentParser(add_help=False)
    base_parser.add_argument("--json", action="store_true", help="Output results in JSON format")

    parser = argparse.ArgumentParser(
        prog="r0nt",
        description="Tamper-evident backup verification system (Phase 2)",
        parents=[base_parser],
    )
    parser.add_argument("--config", help="Custom path to profiles.toml")

    subparsers = parser.add_subparsers(dest="command")

    # init
    p_init = subparsers.add_parser("init", parents=[base_parser], help="Generate keys and initialize witness DB")
    p_init.add_argument("--key", default="r0nt_key.pem", help="Path to write Ed25519 private key")
    p_init.add_argument("--pubkey", default="r0nt_key.pub.pem", help="Path to write Ed25519 public key")
    p_init.add_argument("--encrypt", action="store_true", help="Encrypt private key with a passphrase")
    p_init.add_argument("-f", "--force", action="store_true", help="Overwrite existing key files")

    # backup
    p_backup = subparsers.add_parser("backup", parents=[base_parser], help="Create a signed backup snapshot")
    p_backup.add_argument("--profile", help="Profile name to use")
    p_backup.add_argument("source", nargs="?", help="Source directory (direct mode)")
    p_backup.add_argument("--repo", help="Repository path (direct mode)")
    p_backup.add_argument("--key", help="Private key path (direct mode)")
    p_backup.add_argument("--witness-db", help="Witness DB path (direct mode)")
    p_backup.add_argument("--chunk-size", type=int, default=1024 * 1024, help="Chunk size")
    p_backup.add_argument("--dry-run", action="store_true", help="Simulate backup without writing")

    # verify
    p_verify = subparsers.add_parser("verify", parents=[base_parser], help="Verify repository integrity against witness DB")
    p_verify.add_argument("--profile", help="Profile name to use")
    p_verify.add_argument("--repo", help="Repository path (direct mode)")
    p_verify.add_argument("--pubkey", help="Pinned public key path (direct mode)")
    p_verify.add_argument("--witness-db", help="Witness DB path (direct mode)")
    p_verify.add_argument("--mode", choices=["quick", "full", "sample"], default="full", help="Verification mode")
    p_verify.add_argument("--percent", type=float, default=10.0, help="Sample percentage for sample mode")

    # restore
    p_restore = subparsers.add_parser("restore", parents=[base_parser], help="Restore files from a snapshot")
    p_restore.add_argument("snapshot", help="Snapshot backup_id or sequence_number to restore")
    p_restore.add_argument("--target", required=True, help="Destination directory")
    p_restore.add_argument("--profile", help="Profile name")
    p_restore.add_argument("--path", action="append", help="Filter path prefix to restore")
    p_restore.add_argument("--allow-nonempty", action="store_true", help="Allow restoring into non-empty directory")
    p_restore.add_argument("--overwrite", action="store_true", help="Allow overwriting existing files")

    # list
    p_list = subparsers.add_parser("list", parents=[base_parser], help="List snapshots in repository")
    p_list.add_argument("--profile", help="Profile name")

    # show
    p_show = subparsers.add_parser("show", parents=[base_parser], help="Show snapshot details")
    p_show.add_argument("snapshot", help="Snapshot backup_id or sequence_number")
    p_show.add_argument("--profile", help="Profile name")
    p_show.add_argument("--path", help="Filter file prefix")

    # diff
    p_diff = subparsers.add_parser("diff", parents=[base_parser], help="Diff two snapshots")
    p_diff.add_argument("snapshotA", help="First snapshot")
    p_diff.add_argument("snapshotB", help="Second snapshot")
    p_diff.add_argument("--profile", help="Profile name")

    # profile
    p_prof = subparsers.add_parser("profile", parents=[base_parser], help="Profile management")
    prof_sub = p_prof.add_subparsers(dest="profile_action", required=True)
    prof_sub.add_parser("list", parents=[base_parser], help="List profile names")
    p_prof_show = prof_sub.add_parser("show", parents=[base_parser], help="Show profile details")
    p_prof_show.add_argument("name", help="Profile name")
    p_prof_rm = prof_sub.add_parser("remove", parents=[base_parser], help="Remove a profile")
    p_prof_rm.add_argument("name", help="Profile name")
    p_prof_use = prof_sub.add_parser("use", parents=[base_parser], help="Set active default profile")
    p_prof_use.add_argument("name", help="Profile name to set as default")

    # key
    p_key = subparsers.add_parser("key", parents=[base_parser], help="Key utilities")
    key_sub = p_key.add_subparsers(dest="key_action", required=True)
    p_k_info = key_sub.add_parser("info", parents=[base_parser], help="Display key ID and encryption status")
    p_k_info.add_argument("--profile", help="Profile name")
    p_k_exp = key_sub.add_parser("export-public", parents=[base_parser], help="Export public key PEM")
    p_k_exp.add_argument("out_file", help="Destination path for public key")
    p_k_exp.add_argument("--profile", help="Profile name")

    # history
    p_hist = subparsers.add_parser("history", parents=[base_parser], help="Show past verification runs")
    p_hist.add_argument("--profile", help="Profile name")

    # schedule-help
    p_sched = subparsers.add_parser("schedule-help", parents=[base_parser], help="Print scheduler commands")
    p_sched.add_argument("--profile", help="Profile name")

    # anchor
    p_anchor = subparsers.add_parser("anchor", parents=[base_parser], help="External anchoring commands")
    anchor_sub = p_anchor.add_subparsers(dest="anchor_action", required=True)
    p_a_run = anchor_sub.add_parser("run", parents=[base_parser], help="Batch unanchored manifests and submit")
    p_a_run.add_argument("--profile", help="Profile name")
    p_a_run.add_argument("--backend", default="fake", choices=["fake", "ots"], help="Anchor backend (fake or ots)")

    p_a_up = anchor_sub.add_parser("upgrade", parents=[base_parser], help="Poll for confirmation proofs")
    p_a_up.add_argument("--profile", help="Profile name")
    p_a_up.add_argument("--backend", default="fake", choices=["fake", "ots"], help="Anchor backend (fake or ots)")

    p_a_st = anchor_sub.add_parser("status", parents=[base_parser], help="Display anchor batch statistics")
    p_a_st.add_argument("--profile", help="Profile name")

    p_a_vf = anchor_sub.add_parser("verify", parents=[base_parser], help="Verify anchor proofs and coverage")
    p_a_vf.add_argument("--profile", help="Profile name")
    p_a_vf.add_argument("--backend", default="fake", choices=["fake", "ots"], help="Anchor backend (fake or ots)")
    p_a_vf.add_argument("--grace-hours", type=int, default=24, help="Unanchored window grace period (hours)")

    # restore-test
    p_rt = subparsers.add_parser("restore-test", parents=[base_parser], help="Run synthetic restore testing on sample")
    p_rt.add_argument("--profile", help="Profile name")
    p_rt.add_argument("--snapshot", help="Snapshot backup_id or sequence number (default: latest)")
    p_rt.add_argument("--sample", type=int, help="Sample file count")
    p_rt.add_argument("--percent", type=float, help="Sample percentage")
    p_rt.add_argument("--workdir", help="Explicit isolated working directory")

    # status
    p_status = subparsers.add_parser("status", parents=[base_parser], help="Display one-screen health summary")
    p_status.add_argument("--profile", help="Profile name (default: default_profile from config)")
    p_status.add_argument("--strict", action="store_true", help="Exit with code 1 if any warnings are detected")
    return parser


def main(argv: list[str] | None = None) -> int:
    _setup_logging()
    parser = build_parser()

    # If launched with no arguments at all, print help
    if (argv is None and len(sys.argv) <= 1) or (argv is not None and len(argv) == 0):
        parser.print_help()
        return EXIT_CLEAN

    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return EXIT_USAGE_ERROR if exc.code != 0 else EXIT_CLEAN

    if not args.command:
        parser.print_help()
        return EXIT_CLEAN

    cfg_path = Path(args.config) if args.config else None
    pm = ProfileManager(cfg_path)

    try:
        cmd_map = {
            "init": cmd_init,
            "backup": cmd_backup,
            "verify": cmd_verify,
            "restore": cmd_restore,
            "list": cmd_list,
            "show": cmd_show,
            "diff": cmd_diff,
            "profile": cmd_profile,
            "key": cmd_key,
            "history": cmd_history,
            "schedule-help": cmd_schedule_help,
            "anchor": cmd_anchor,
            "restore-test": cmd_restore_test,
            "status": cmd_status,
        }
        handler = cmd_map.get(args.command)
        if handler:
            return handler(args, pm)
        return EXIT_USAGE_ERROR

    except KeyboardInterrupt:
        return EXIT_CANCELLED
    except ValueError as exc:
        print(f"Configuration or Usage Error: {exc}", file=sys.stderr)
        return EXIT_USAGE_ERROR
    except (FileNotFoundError, PermissionError, OSError) as exc:
        print(f"Operational Failure: {exc}", file=sys.stderr)
        return EXIT_OPERATIONAL_FAILURE
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return EXIT_OPERATIONAL_FAILURE


if __name__ == "__main__":
    sys.exit(main())
