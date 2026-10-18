"""Service layer for r0nt (SPEC_PHASE2 §1).

Central business-logic boundary decoupling CLI and TUI from core domain operations.
Functions return typed dataclasses, support progress callbacks and cancellation tokens,
and perform zero console printing or prompt interactions.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Literal

from r0nt.anchor import (
    build_anchor_batch,
    generate_anchor_key,
    run_anchor_batch,
    upgrade_anchors,
    verify_anchors,
)
from r0nt.anchor_backends import get_anchor_backend
from r0nt.chain import Finding
from r0nt.chunker import scan_sources
from r0nt.diff import DiffResult, SnapshotDetail, SnapshotSummary, diff_snapshots, get_snapshot_detail, list_snapshots
from r0nt.heuristics import RiskFlag, analyze_snapshot_risk
from r0nt.manifest import build_manifest, manifest_hash
from r0nt.matcher import PathMatcher
from r0nt.profile import Profile, ProfileManager
from r0nt.restore import RestoreResult, restore_snapshot
from r0nt.restoretest import RestoreTestFailure, RestoreTestResult, run_restore_test
from r0nt.signing import (
    compute_key_id,
    derive_witness_key,
    export_public_key as sign_export_public_key,
    generate_keypair,
    is_private_key_encrypted,
    load_private_key,
    load_public_key,
    save_private_key,
    save_public_key,
)
from r0nt.store import ChunkStore, ManifestStore, WitnessDB
from r0nt.verify import verify_with_stats


# =========================================================================
# Result Dataclasses
# =========================================================================

@dataclass
class BackupResult:
    """Summary of a backup operation."""
    backup_id: str | None = None
    sequence_number: int | None = None
    created_at: str | None = None
    files_backed_up: int = 0
    skipped_files: int = 0
    new_chunks: int = 0
    dedup_chunks: int = 0
    total_chunks: int = 0
    total_bytes: int = 0
    root_hash: str | None = None
    manifest_hash: str | None = None
    cancelled: bool = False
    dry_run: bool = False
    warnings: list[str] = field(default_factory=list)


@dataclass
class VerifyResult:
    """Summary of a verification run."""
    is_clean: bool
    finding_count: int
    findings: list[Finding]
    stats: dict[str, Any]
    snapshots_checked: int
    warnings: list[str] = field(default_factory=list)
    risk_flags: list[RiskFlag] = field(default_factory=list)

    @property
    def has_risk(self) -> bool:
        return len(self.risk_flags) > 0


@dataclass
class KeyInfo:
    """Status and metadata for a keypair."""
    key_id: str
    private_key_path: str
    public_key_path: str
    encrypted: bool
    permissions_ok: bool
    warnings: list[str] = field(default_factory=list)


@dataclass
class VerificationHistoryItem:
    """A single record from the verification history."""
    id: int
    run_at: str
    backup_id: str | None
    result: str
    finding_count: int
    findings: list[dict] = field(default_factory=list)


@dataclass
class StatusResult:
    """One-screen aggregated health summary for a profile."""
    profile_name: str
    snapshot_count: int
    last_backup_time: str | None
    last_backup_relative: str | None
    chain_health: str  # "healthy", "tampered", "empty", or "error"
    last_verify: dict | None
    last_anchor: dict | None
    last_restore_test: dict | None
    warnings: list[str] = field(default_factory=list)

    @property
    def has_warnings(self) -> bool:
        return len(self.warnings) > 0


# =========================================================================
# Co-location & Environment Checks
# =========================================================================

def check_colocation_warning(repo_path: Path, witness_db_path: Path) -> str | None:
    """Warn if repository and witness DB reside on the same drive or volume."""
    r_res = repo_path.resolve()
    w_res = witness_db_path.resolve()
    if r_res.drive and w_res.drive:
        if r_res.drive.lower() == w_res.drive.lower():
            return (
                f"Warning: Witness DB ({w_res}) is on the same drive ({w_res.drive}) as "
                f"repository ({r_res}). An attacker controlling this machine can modify both."
            )
    return None


# =========================================================================
# Backup Service
# =========================================================================

class BackupService:
    """Executes backup workflows driven by Profile or explicit parameters."""

    def run_backup(
        self,
        profile: Profile,
        passphrase: str | None = None,
        dry_run: bool = False,
        progress_callback: Callable[..., None] | None = None,
        cancel_event: Any | None = None,
    ) -> BackupResult:
        warnings: list[str] = []

        repo_path = Path(profile.repo).resolve()
        witness_db_path = Path(profile.witness_db).resolve()
        key_path = Path(profile.key_path).resolve()
        pubkey_path = Path(profile.pubkey_path).resolve()

        # Check co-location warning
        colo_warn = check_colocation_warning(repo_path, witness_db_path)
        if colo_warn:
            warnings.append(colo_warn)

        # Check key encryption
        if key_path.exists() and not is_private_key_encrypted(key_path):
            warnings.append(f"Private key '{key_path}' is stored unencrypted on disk.")

        if cancel_event and cancel_event.is_set():
            return BackupResult(cancelled=True, warnings=warnings)

        private_key = load_private_key(key_path, passphrase=passphrase)
        public_key = private_key.public_key()
        mac_key = derive_witness_key(public_key)

        witness_db = WitnessDB(witness_db_path, mac_key)
        try:
            prev_manifest_hash = witness_db.get_prev_manifest_hash()
            sequence_number = witness_db.get_next_sequence_number()

            matcher = PathMatcher(profile.exclude)
            sources = [(s.label, Path(s.path)) for s in profile.sources]

            file_results, skipped_files = scan_sources(
                sources=sources,
                chunk_size=profile.chunk_size,
                max_file_size=profile.max_file_size,
                max_total_size=profile.max_total_size,
                max_file_count=profile.max_file_count,
                exclude_matcher=matcher,
                progress_callback=progress_callback,
                cancel_event=cancel_event,
            )

            if cancel_event and cancel_event.is_set():
                return BackupResult(cancelled=True, warnings=warnings)

            total_bytes = sum(fr.size for fr in file_results)
            total_chunks = sum(len(fr.chunks) for fr in file_results)

            if dry_run:
                return BackupResult(
                    backup_id="dry-run",
                    sequence_number=sequence_number,
                    files_backed_up=len(file_results),
                    skipped_files=len(skipped_files),
                    total_chunks=total_chunks,
                    total_bytes=total_bytes,
                    dry_run=True,
                    warnings=warnings,
                )

            # Stage 2: Store chunks
            chunk_store = ChunkStore(repo_path)
            manifest_store = ManifestStore(repo_path)

            new_chunks = 0
            dedup_chunks = 0
            for fr in file_results:
                for c in fr.chunks:
                    if cancel_event and cancel_event.is_set():
                        return BackupResult(cancelled=True, warnings=warnings)
                    is_new = chunk_store.write_chunk(c.hash, c.data)
                    if is_new:
                        new_chunks += 1
                    else:
                        dedup_chunks += 1

            if cancel_event and cancel_event.is_set():
                return BackupResult(cancelled=True, warnings=warnings)

            # Stage 3: Build manifest & sign
            manifest = build_manifest(
                file_results=file_results,
                skipped_files=skipped_files,
                chunk_size=profile.chunk_size,
                prev_manifest_hash=prev_manifest_hash,
                sequence_number=sequence_number,
                private_key=private_key,
                public_key=public_key,
            )

            # Stage 4: Atomic manifest write
            manifest_store.write_manifest(manifest)

            # Stage 5: Witness DB commit
            witness_db.record_manifest(manifest)

            m_hash = manifest_hash(manifest)

            return BackupResult(
                backup_id=manifest["backup_id"],
                sequence_number=manifest["sequence_number"],
                created_at=manifest["created_at"],
                files_backed_up=len(file_results),
                skipped_files=len(skipped_files),
                new_chunks=new_chunks,
                dedup_chunks=dedup_chunks,
                total_chunks=total_chunks,
                total_bytes=total_bytes,
                root_hash=manifest["root_hash"],
                manifest_hash=m_hash,
                warnings=warnings,
            )

        finally:
            witness_db.close()


# =========================================================================
# Verify Service
# =========================================================================

class VerifyService:
    """Executes verification workflows and reports results."""

    def run_verify(
        self,
        profile: Profile,
        mode: Literal["quick", "full", "sample"] = "full",
        sample_percent: float = 10.0,
        progress_callback: Callable[..., None] | None = None,
        cancel_event: Any | None = None,
    ) -> VerifyResult:
        warnings: list[str] = []

        repo_path = Path(profile.repo).resolve()
        witness_db_path = Path(profile.witness_db).resolve()
        pubkey_path = Path(profile.pubkey_path).resolve()

        colo_warn = check_colocation_warning(repo_path, witness_db_path)
        if colo_warn:
            warnings.append(colo_warn)

        public_key = load_public_key(pubkey_path)
        mac_key = derive_witness_key(public_key)
        witness_db = WitnessDB(witness_db_path, mac_key)

        try:
            findings, stats = verify_with_stats(
                repo_path=repo_path,
                source_path=None,
                public_key=public_key,
                witness_db=witness_db,
                mode=mode,
                sample_percent=sample_percent,
                progress_callback=progress_callback,
                cancel_event=cancel_event,
            )

            latest_rec = witness_db.get_latest_record()
            latest_id = latest_rec["backup_id"] if latest_rec else None
            result_str = "clean" if not findings else "findings"
            findings_dicts = [f._asdict() for f in findings]

            witness_db.record_verification(latest_id, result_str, findings_dicts)

            # Heuristics analysis over consecutive snapshots
            risk_flags: list[RiskFlag] = []
            try:
                manifest_store = ManifestStore(repo_path)
                manifests = sorted(
                    manifest_store.load_all_manifests(),
                    key=lambda m: m.get("sequence_number", 0),
                )
                if len(manifests) >= 2:
                    chunk_store = ChunkStore(repo_path)
                    prev_m = manifests[-2]
                    curr_m = manifests[-1]
                    risk_flags = analyze_snapshot_risk(prev_m, curr_m, chunk_store)
            except Exception:
                pass

            return VerifyResult(
                is_clean=(len(findings) == 0),
                finding_count=len(findings),
                findings=findings,
                stats=stats,
                snapshots_checked=stats.get("snapshots_checked", 0),
                warnings=warnings,
                risk_flags=risk_flags,
            )

        finally:
            witness_db.close()


# =========================================================================
# Restore Service
# =========================================================================

class RestoreService:
    """Restores files from a snapshot."""

    def run_restore(
        self,
        profile: Profile,
        snapshot_id: str | int,
        target_dir: Path,
        paths: list[str] | None = None,
        allow_nonempty: bool = False,
        overwrite: bool = False,
        progress_callback: Callable[..., None] | None = None,
        cancel_event: Any | None = None,
    ) -> RestoreResult:
        repo_path = Path(profile.repo).resolve()
        witness_db_path = Path(profile.witness_db).resolve()
        pubkey_path = Path(profile.pubkey_path).resolve()

        public_key = load_public_key(pubkey_path)
        mac_key = derive_witness_key(public_key)
        witness_db = WitnessDB(witness_db_path, mac_key)

        manifest_store = ManifestStore(repo_path)
        all_manifests = manifest_store.load_all_manifests()

        manifest: dict | None = None
        ident_str = str(snapshot_id).strip()
        for m in all_manifests:
            if m.get("backup_id") == ident_str or m.get("backup_id", "").startswith(ident_str):
                manifest = m
                break
        if manifest is None:
            try:
                seq = int(ident_str)
                for m in all_manifests:
                    if m.get("sequence_number") == seq:
                        manifest = m
                        break
            except ValueError:
                pass

        if manifest is None:
            witness_db.close()
            raise FileNotFoundError(f"Snapshot '{snapshot_id}' not found in repository.")

        try:
            return restore_snapshot(
                manifest=manifest,
                repo_path=repo_path,
                target_dir=target_dir,
                public_key=public_key,
                witness_db=witness_db,
                paths=paths,
                allow_nonempty=allow_nonempty,
                overwrite=overwrite,
                progress_callback=progress_callback,
                cancel_event=cancel_event,
            )
        finally:
            witness_db.close()


# =========================================================================
# Key Service
# =========================================================================

class KeyService:
    """Key generation, inspection, and public key export."""

    def get_key_info(self, key_path: Path, pubkey_path: Path) -> KeyInfo:
        key_path = Path(key_path).resolve()
        pubkey_path = Path(pubkey_path).resolve()
        warnings: list[str] = []

        if not pubkey_path.exists():
            raise FileNotFoundError(f"Public key not found: {pubkey_path}")

        pub = load_public_key(pubkey_path)
        key_id = compute_key_id(pub)

        encrypted = False
        if key_path.exists():
            encrypted = is_private_key_encrypted(key_path)
            if not encrypted:
                warnings.append(f"Private key at '{key_path}' is stored unencrypted.")

        return KeyInfo(
            key_id=key_id,
            private_key_path=str(key_path),
            public_key_path=str(pubkey_path),
            encrypted=encrypted,
            permissions_ok=True,
            warnings=warnings,
        )

    def generate_keypair_files(
        self,
        key_path: Path,
        pubkey_path: Path,
        passphrase: str | None = None,
        force: bool = False,
    ) -> KeyInfo:
        key_path = Path(key_path).resolve()
        pubkey_path = Path(pubkey_path).resolve()

        if key_path.exists() and not force:
            raise FileExistsError(f"Private key file already exists: {key_path}")
        if pubkey_path.exists() and not force:
            raise FileExistsError(f"Public key file already exists: {pubkey_path}")

        priv, pub = generate_keypair()
        save_private_key(priv, key_path, passphrase=passphrase)
        save_public_key(pub, pubkey_path)

        return self.get_key_info(key_path, pubkey_path)

    def export_public_key(self, pubkey_path: Path, out_path: Path) -> None:
        pub = load_public_key(Path(pubkey_path))
        sign_export_public_key(pub, Path(out_path))


# =========================================================================
# Profile & History Services
# =========================================================================

class ProfileService:
    """CRUD operations for profiles."""

    def __init__(self, config_path: Path | None = None) -> None:
        self.manager = ProfileManager(config_path)

    def list_profiles(self) -> list[str]:
        return self.manager.list_profiles()

    def get_profile(self, name: str) -> Profile | None:
        return self.manager.get_profile(name)

    def save_profile(self, profile: Profile) -> None:
        self.manager.save_profile(profile)

    def delete_profile(self, name: str) -> bool:
        return self.manager.delete_profile(name)


class HistoryService:
    """Queries verification history and formats reports."""

    def get_history(self, profile: Profile) -> list[VerificationHistoryItem]:
        witness_db_path = Path(profile.witness_db).resolve()
        if not witness_db_path.exists():
            return []

        pubkey = load_public_key(Path(profile.pubkey_path))
        mac_key = derive_witness_key(pubkey)
        witness_db = WitnessDB(witness_db_path, mac_key)

        try:
            cur = witness_db.conn.execute(
                "SELECT id, run_at, backup_id, result, finding_count, findings_json "
                "FROM verification_history ORDER BY id DESC"
            )
            items: list[VerificationHistoryItem] = []
            for row in cur.fetchall():
                try:
                    findings_data = json.loads(row["findings_json"])
                except Exception:
                    findings_data = []
                items.append(VerificationHistoryItem(
                    id=row["id"],
                    run_at=row["run_at"],
                    backup_id=row["backup_id"],
                    result=row["result"],
                    finding_count=row["finding_count"],
                    findings=findings_data,
                ))
            return items
        finally:
            witness_db.close()


# =========================================================================
# Anchor Service
# =========================================================================

def get_or_create_anchor_key(witness_db_path: Path) -> bytes:
    """Retrieve or generate the 256-bit anchor HMAC key stored alongside witness DB."""
    key_file = witness_db_path.parent / "anchor.key"
    if key_file.exists():
        return key_file.read_bytes()
    key = generate_anchor_key()
    key_file.write_bytes(key)
    try:
        os.chmod(key_file, 0o600)
    except Exception:
        pass
    return key


class AnchorService:
    """Orchestrates external anchoring operations for a profile."""

    def run_anchor(self, profile: Profile, backend_name: str = "fake") -> dict:
        witness_db_path = Path(profile.witness_db).resolve()
        pubkey = load_public_key(Path(profile.pubkey_path))
        mac_key = derive_witness_key(pubkey)
        witness_db = WitnessDB(witness_db_path, mac_key)
        anchor_key = get_or_create_anchor_key(witness_db_path)
        backend = get_anchor_backend(backend_name)
        try:
            return run_anchor_batch(witness_db, anchor_key, backend, backend_name=backend_name)
        finally:
            witness_db.close()

    def upgrade_anchors(self, profile: Profile, backend_name: str = "fake") -> list[dict]:
        witness_db_path = Path(profile.witness_db).resolve()
        pubkey = load_public_key(Path(profile.pubkey_path))
        mac_key = derive_witness_key(pubkey)
        witness_db = WitnessDB(witness_db_path, mac_key)
        backend = get_anchor_backend(backend_name)
        try:
            return upgrade_anchors(witness_db, backend)
        finally:
            witness_db.close()

    def get_status(self, profile: Profile) -> dict:
        witness_db_path = Path(profile.witness_db).resolve()
        pubkey = load_public_key(Path(profile.pubkey_path))
        mac_key = derive_witness_key(pubkey)
        witness_db = WitnessDB(witness_db_path, mac_key)
        try:
            anchors = witness_db.get_all_anchors()
            unanchored = witness_db.get_unanchored_manifests()
            pending_count = sum(1 for a in anchors if a.get("status") == "pending")
            confirmed_count = sum(1 for a in anchors if a.get("status") == "confirmed")
            latest_anchor = anchors[-1] if anchors else None
            return {
                "total_anchors": len(anchors),
                "unanchored_manifests": len(unanchored),
                "pending_count": pending_count,
                "confirmed_count": confirmed_count,
                "latest_anchor": latest_anchor,
            }
        finally:
            witness_db.close()

    def verify_anchors(
        self,
        profile: Profile,
        backend_name: str = "fake",
        grace_hours: int = 24,
    ) -> list[dict]:
        witness_db_path = Path(profile.witness_db).resolve()
        pubkey = load_public_key(Path(profile.pubkey_path))
        mac_key = derive_witness_key(pubkey)
        witness_db = WitnessDB(witness_db_path, mac_key)
        anchor_key = get_or_create_anchor_key(witness_db_path)
        backend = get_anchor_backend(backend_name)
        try:
            return verify_anchors(witness_db, anchor_key, backend, anchor_grace_hours=grace_hours)
        finally:
            witness_db.close()


# =========================================================================
# Restore-Test Service
# =========================================================================

class RestoreTestService:
    """Orchestrates restore testing on snapshot samples."""

    def run_test(
        self,
        profile: Profile,
        snapshot_id: str | int | None = None,
        sample_count: int | None = None,
        sample_percent: float | None = None,
        workdir: Path | None = None,
        seed: int | None = None,
        cancel_event: Any | None = None,
        progress_callback: Any | None = None,
    ) -> RestoreTestResult:
        repo_path = Path(profile.repo).resolve()
        witness_db_path = Path(profile.witness_db).resolve()
        pubkey_path = Path(profile.pubkey_path).resolve()
        source_paths = [Path(s.path).resolve() for s in profile.sources]

        public_key = load_public_key(pubkey_path)
        mac_key = derive_witness_key(public_key)
        witness_db = WitnessDB(witness_db_path, mac_key)

        manifest_store = ManifestStore(repo_path)
        all_manifests = sorted(
            manifest_store.load_all_manifests(),
            key=lambda m: m.get("sequence_number", 0),
        )
        if not all_manifests:
            witness_db.close()
            raise FileNotFoundError("No snapshots found in repository to test.")

        manifest: dict | None = None
        if snapshot_id is not None:
            ident_str = str(snapshot_id).strip()
            for m in all_manifests:
                if m.get("backup_id") == ident_str or m.get("backup_id", "").startswith(ident_str):
                    manifest = m
                    break
            if manifest is None:
                try:
                    seq = int(ident_str)
                    for m in all_manifests:
                        if m.get("sequence_number") == seq:
                            manifest = m
                            break
                except ValueError:
                    pass
            if manifest is None:
                witness_db.close()
                raise FileNotFoundError(f"Snapshot '{snapshot_id}' not found.")
        else:
            manifest = all_manifests[-1]

        try:
            return run_restore_test(
                manifest=manifest,
                repo_path=repo_path,
                witness_db=witness_db,
                source_paths=source_paths,
                workdir=workdir,
                sample_count=sample_count,
                sample_percent=sample_percent,
                seed=seed,
                cancel_event=cancel_event,
                progress_callback=progress_callback,
            )
        finally:
            witness_db.close()


# =========================================================================
# Status Service
# =========================================================================

class StatusService:
    """Aggregates system health, snapshot state, verification, anchoring, and test status."""

    def get_status(self, profile: Profile) -> StatusResult:
        repo_path = Path(profile.repo).resolve()
        witness_db_path = Path(profile.witness_db).resolve()
        key_path = Path(profile.key_path).resolve()
        pubkey_path = Path(profile.pubkey_path).resolve()

        warnings: list[str] = []

        # 1. Warning: Same drive
        try:
            repo_drive = os.path.splitdrive(str(repo_path))[0].upper()
            wdb_drive = os.path.splitdrive(str(witness_db_path))[0].upper()
            if repo_drive and wdb_drive and repo_drive == wdb_drive:
                warnings.append(f"Witness DB and repository are on the same drive ({repo_drive})")
        except Exception:
            pass

        # 2. Warning: Unencrypted private key
        try:
            if key_path.exists():
                if not is_private_key_encrypted(key_path):
                    warnings.append(f"Private key '{key_path.name}' is unencrypted (passphrase recommended)")
            else:
                warnings.append(f"Private key file not found: {key_path}")
        except Exception:
            pass

        # 3. Snapshot count & last backup
        snapshots: list[SnapshotSummary] = []
        if repo_path.exists() and pubkey_path.exists():
            try:
                public_key = load_public_key(pubkey_path)
                snapshots = list_snapshots(repo_path, public_key)
            except Exception:
                snapshots = []

        snapshot_count = len(snapshots)
        last_backup_time: str | None = None
        last_backup_relative: str | None = None

        if snapshot_count > 0:
            last_sn = snapshots[-1]
            last_backup_time = last_sn.created_at
            last_backup_relative = self._format_relative(last_backup_time)
            # Check backup age warning (> 7 days)
            age_days = self._get_age_days(last_backup_time)
            if age_days is not None and age_days > 7:
                warnings.append(f"No backup created in {age_days} days")
        else:
            warnings.append("No backups found in repository")

        # 4. Chain health
        chain_health = "unknown"
        if snapshot_count == 0:
            chain_health = "empty"
        elif repo_path.exists() and witness_db_path.exists() and pubkey_path.exists():
            try:
                v_res = VerifyService().run_verify(profile, mode="quick")
                chain_health = "healthy" if len(v_res.findings) == 0 else "tampered"
            except Exception:
                chain_health = "error"

        # 5. Last verify history
        last_verify_info: dict | None = None
        try:
            history = HistoryService().get_verify_history(profile)
            if history:
                latest_vh = history[0]
                last_verify_info = {
                    "timestamp": latest_vh.get("timestamp"),
                    "relative": self._format_relative(latest_vh.get("timestamp")),
                    "mode": latest_vh.get("mode"),
                    "result": "CLEAN" if latest_vh.get("exit_code") == 0 else "FINDINGS",
                    "findings_count": latest_vh.get("findings_count", 0),
                }
            else:
                warnings.append("Repository has never been verified")
        except Exception:
            warnings.append("Repository has never been verified")

        # 6. Last anchor status
        last_anchor_info: dict | None = None
        try:
            astat = AnchorService().get_status(profile)
            last_anchor_info = {
                "total_anchors": astat.get("total_anchors", 0),
                "pending_count": astat.get("pending_count", 0),
                "confirmed_count": astat.get("confirmed_count", 0),
                "unanchored_manifests": astat.get("unanchored_manifests", 0),
            }
            if astat.get("latest_anchor"):
                la = astat["latest_anchor"]
                last_anchor_info["latest_id"] = la.get("id")
                last_anchor_info["latest_status"] = la.get("status")
                last_anchor_info["latest_created_at"] = la.get("created_at")
        except Exception:
            pass

        # 7. Last restore-test result
        last_rt_info: dict | None = None
        if witness_db_path.exists() and pubkey_path.exists():
            try:
                public_key = load_public_key(pubkey_path)
                mac_key = derive_witness_key(public_key)
                wdb = WitnessDB(witness_db_path, mac_key)
                try:
                    rt_history = wdb.get_restore_test_history(limit=1)
                    if rt_history:
                        latest_rt = rt_history[0]
                        last_rt_info = {
                            "run_at": latest_rt.get("run_at"),
                            "relative": self._format_relative(latest_rt.get("run_at")),
                            "status": latest_rt.get("status"),
                            "sample_count": latest_rt.get("sample_count", 0),
                            "failed_count": latest_rt.get("failed_count", 0),
                        }
                finally:
                    wdb.close()
            except Exception:
                pass

        return StatusResult(
            profile_name=profile.name,
            snapshot_count=snapshot_count,
            last_backup_time=last_backup_time,
            last_backup_relative=last_backup_relative,
            chain_health=chain_health,
            last_verify=last_verify_info,
            last_anchor=last_anchor_info,
            last_restore_test=last_rt_info,
            warnings=warnings,
        )

    def _format_relative(self, dt_str: str | None) -> str | None:
        if not dt_str:
            return None
        try:
            from datetime import datetime, timezone
            clean_str = dt_str.replace("Z", "+00:00")
            dt = datetime.fromisoformat(clean_str)
            now = datetime.now(timezone.utc)
            diff = now - dt
            seconds = int(diff.total_seconds())
            if seconds < 0:
                return "just now"
            if seconds < 60:
                return f"{seconds}s ago"
            minutes = seconds // 60
            if minutes < 60:
                return f"{minutes}m ago"
            hours = minutes // 60
            if hours < 24:
                return f"{hours}h ago"
            days = hours // 24
            return f"{days}d ago"
        except Exception:
            return dt_str

    def _get_age_days(self, dt_str: str | None) -> int | None:
        if not dt_str:
            return None
        try:
            from datetime import datetime, timezone
            clean_str = dt_str.replace("Z", "+00:00")
            dt = datetime.fromisoformat(clean_str)
            now = datetime.now(timezone.utc)
            return max(0, (now - dt).days)
        except Exception:
            return None
