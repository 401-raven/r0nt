"""Automated restore testing subsystem (SPEC_PHASE3 §3, T-40).

Performs lightweight synthetic restore tests against a random sample of backup files:
1. Reconstructs files from chunks in an isolated temporary workdir (strictly outside repo/sources).
2. Verifies chunk SHA-256 hashes and file Merkle roots.
3. Performs type-specific integrity/health checks (zip testzip, JSON parse, SQLite integrity, magic bytes).
4. Writes HMAC-protected results into the witness DB.
5. Reliably cleans up working directories upon completion, failure, or cancellation.
"""

from __future__ import annotations

import hashlib
import hmac as hmac_mod
import json
import logging
import os
from pathlib import Path
import random
import shutil
import sqlite3
import tempfile
import time
from dataclasses import asdict, dataclass, field
from typing import Any
import zipfile

from r0nt.merkle import MerkleTree
from r0nt.store import ChunkStore, WitnessDB

logger = logging.getLogger(__name__)

# File extension groups for type-specific health checks
ZIP_EXTENSIONS = {".zip", ".docx", ".xlsx", ".pptx", ".odt", ".ods", ".jar", ".apk"}
JSON_EXTENSIONS = {".json"}
SQLITE_EXTENSIONS = {".sqlite", ".sqlite3", ".db"}
TEXT_EXTENSIONS = {
    ".txt", ".py", ".md", ".csv", ".rst", ".toml", ".yaml", ".yml",
    ".sh", ".bat", ".ps1", ".html", ".htm", ".css", ".js", ".ts",
    ".xml", ".ini", ".cfg", ".conf",
}


@dataclass
class RestoreTestFailure:
    """Detailed record of a file restoration or integrity check failure."""
    path: str
    reason: str
    stage: str  # "chunk_read", "merkle_root", "type_check"


@dataclass
class RestoreTestResult:
    """Summary of a restore test run."""
    backup_id: str
    status: str  # "passed", "failed", "cancelled"
    sample_count: int
    passed_count: int
    failed_count: int
    failures: list[RestoreTestFailure] = field(default_factory=list)
    duration_seconds: float = 0.0
    workdir: str = ""

    @property
    def exit_code(self) -> int:
        """Map restore test outcome to standard SPEC_PHASE2 §3 exit codes."""
        if self.status == "passed":
            return 0
        elif self.status == "cancelled":
            return 130
        else:
            return 1


def check_file_health(file_path: Path) -> tuple[bool, str]:
    """Perform lightweight 'opens correctly' checks based on file extension and magic bytes.

    Returns:
        (is_healthy: bool, details: str)
    """
    if not file_path.is_file():
        return False, f"File does not exist: {file_path}"

    ext = file_path.suffix.lower()

    # 1. Zip archives and zipped document containers
    if ext in ZIP_EXTENSIONS:
        try:
            with zipfile.ZipFile(file_path, "r") as zf:
                bad_file = zf.testzip()
                if bad_file is not None:
                    return False, f"Corrupted zip archive entry: {bad_file}"
                return True, "Zip archive structure and CRCs valid"
        except Exception as exc:
            return False, f"Zip verification error: {exc}"

    # 2. JSON files
    if ext in JSON_EXTENSIONS:
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                json.load(f)
            return True, "Valid JSON syntax"
        except Exception as exc:
            return False, f"JSON syntax error: {exc}"

    # 3. SQLite databases
    if ext in SQLITE_EXTENSIONS:
        try:
            # Open read-only to avoid journal creation
            uri_path = f"file:{file_path.as_posix()}?mode=ro"
            conn = sqlite3.connect(uri_path, uri=True)
            try:
                row = conn.execute("PRAGMA integrity_check(1);").fetchone()
                if not row or row[0].lower() != "ok":
                    return False, f"SQLite integrity check failed: {row[0] if row else 'empty'}"
                return True, "SQLite database integrity valid"
            finally:
                conn.close()
        except Exception as exc:
            return False, f"SQLite error: {exc}"

    # 4. PNG images
    if ext == ".png":
        try:
            with open(file_path, "rb") as f:
                header = f.read(8)
            if header != b"\x89PNG\r\n\x1a\n":
                return False, f"Invalid PNG signature bytes: {header!r}"
            return True, "Valid PNG signature"
        except Exception as exc:
            return False, f"Error reading PNG: {exc}"

    # 5. JPEG images
    if ext in (".jpg", ".jpeg"):
        try:
            with open(file_path, "rb") as f:
                header = f.read(3)
            if header != b"\xff\xd8\xff":
                return False, f"Invalid JPEG SOI marker: {header!r}"
            return True, "Valid JPEG marker"
        except Exception as exc:
            return False, f"Error reading JPEG: {exc}"

    # 6. PDF documents
    if ext == ".pdf":
        try:
            with open(file_path, "rb") as f:
                header = f.read(5)
            if header != b"%PDF-":
                return False, f"Invalid PDF header: {header!r}"
            return True, "Valid PDF header"
        except Exception as exc:
            return False, f"Error reading PDF: {exc}"

    # 7. Plain text and scripts
    if ext in TEXT_EXTENSIONS:
        try:
            with open(file_path, "r", encoding="utf-8", errors="strict") as f:
                f.read(64 * 1024)  # sample first 64KB
            return True, "Valid UTF-8 text"
        except UnicodeDecodeError as exc:
            return False, f"Text encoding error (non UTF-8): {exc}"
        except Exception as exc:
            return False, f"Error reading text file: {exc}"

    # 8. Unknown / opaque binary types pass purely on hash match
    return True, "Hash match (untyped binary file)"


def select_sample(
    files: list[dict],
    sample_count: int | None = None,
    sample_percent: float | None = None,
    seed: int | None = None,
) -> list[dict]:
    """Select a random or configured sample of files from a manifest.

    Default: 20 files or 5% of total files, whichever is smaller, but at least 1.
    """
    total = len(files)
    if total == 0:
        return []

    if sample_count is not None:
        count = max(1, min(sample_count, total))
    elif sample_percent is not None:
        count = max(1, min(int(round(total * (sample_percent / 100.0))), total))
    else:
        # Default: min(20, 5% of total, at least 1)
        five_percent = max(1, int(round(total * 0.05)))
        count = min(20, five_percent)

    count = min(count, total)
    rng = random.Random(seed) if seed is not None else random.Random()
    return rng.sample(files, count)


def validate_workdir_safety(
    workdir: Path,
    repo_path: Path,
    source_paths: list[Path] | None = None,
) -> None:
    """Ensure workdir is strictly isolated and not inside the repo or source folders."""
    resolved_workdir = workdir.resolve()
    resolved_repo = repo_path.resolve()

    # Reject if workdir is inside repo or repo is inside workdir
    try:
        resolved_workdir.relative_to(resolved_repo)
        raise ValueError(
            f"Restore-test workdir '{workdir}' cannot be inside repository '{repo_path}'"
        )
    except ValueError as exc:
        if "cannot be inside" in str(exc):
            raise
        # Not relative, good

    try:
        resolved_repo.relative_to(resolved_workdir)
        raise ValueError(
            f"Repository '{repo_path}' cannot be inside restore-test workdir '{workdir}'"
        )
    except ValueError as exc:
        if "cannot be inside" in str(exc):
            raise

    # Reject if workdir is inside any source folder
    if source_paths:
        for sp in source_paths:
            resolved_sp = sp.resolve()
            try:
                resolved_workdir.relative_to(resolved_sp)
                raise ValueError(
                    f"Restore-test workdir '{workdir}' cannot be inside source folder '{sp}'"
                )
            except ValueError as exc:
                if "cannot be inside" in str(exc):
                    raise


def run_restore_test(
    manifest: dict,
    repo_path: Path,
    witness_db: WitnessDB | None = None,
    source_paths: list[Path] | None = None,
    workdir: Path | None = None,
    sample_count: int | None = None,
    sample_percent: float | None = None,
    seed: int | None = None,
    cancel_event: Any = None,
    progress_callback: Any = None,
) -> RestoreTestResult:
    """Run an automated restore test over sampled snapshot files.

    Args:
        manifest: Deserialized backup manifest dictionary.
        repo_path: Path to repository root.
        witness_db: Optional witness database to record results.
        source_paths: Optional list of source directory paths to verify safety.
        workdir: Optional isolated directory. If None, a temporary directory is created and cleaned up.
        sample_count: Explicit sample file count.
        sample_percent: Explicit sample percentage (e.g. 10.0 for 10%).
        seed: Random seed for deterministic sample selection.
        cancel_event: Optional threading.Event for cancellation.
        progress_callback: Optional callable(tested_count, total_sample, current_path).

    Returns:
        RestoreTestResult summary.
    """
    start_time = time.time()
    backup_id = manifest.get("backup_id", "unknown")
    all_files = manifest.get("files", [])

    # 1. Determine and validate working directory
    is_temp_workdir = False
    if workdir is not None:
        workdir = Path(workdir).resolve()
        validate_workdir_safety(workdir, repo_path, source_paths)
        workdir.mkdir(parents=True, exist_ok=True)
    else:
        temp_dir_obj = tempfile.TemporaryDirectory(prefix="r0nt_restoretest_")
        workdir = Path(temp_dir_obj.name).resolve()
        is_temp_workdir = True

    failures: list[RestoreTestFailure] = []
    sampled = select_sample(all_files, sample_count, sample_percent, seed)
    passed_count = 0
    status = "passed"

    chunk_store = ChunkStore(repo_path)

    try:
        for idx, fentry in enumerate(sampled):
            if cancel_event and cancel_event.is_set():
                status = "cancelled"
                logger.info("Restore test cancelled by operator for backup %s", backup_id)
                break

            fpath = fentry.get("path", "")
            chunk_hashes = fentry.get("chunks", [])
            expected_root = fentry.get("file_root", "")

            # Progress feedback
            if progress_callback:
                progress_callback(idx, len(sampled), fpath)

            # Stage 1: Read and verify chunks
            chunk_data_list: list[bytes] = []
            chunk_hash_bytes: list[bytes] = []
            read_error = False

            for chash in chunk_hashes:
                if cancel_event and cancel_event.is_set():
                    status = "cancelled"
                    break

                try:
                    cdata = chunk_store.read_chunk(chash)
                    chunk_data_list.append(cdata)
                    chunk_hash_bytes.append(bytes.fromhex(chash))
                except Exception as exc:
                    failures.append(RestoreTestFailure(
                        path=fpath,
                        reason=f"Chunk {chash} missing or corrupted: {exc}",
                        stage="chunk_read",
                    ))
                    read_error = True
                    break

            if status == "cancelled":
                break

            if read_error:
                continue

            # Stage 2: Verify file Merkle tree root
            try:
                tree = MerkleTree(chunk_hash_bytes)
                if not hmac_mod.compare_digest(tree.root_hex, expected_root):
                    failures.append(RestoreTestFailure(
                        path=fpath,
                        reason=f"File Merkle root mismatch: computed {tree.root_hex}, expected {expected_root}",
                        stage="merkle_root",
                    ))
                    continue
            except Exception as exc:
                failures.append(RestoreTestFailure(
                    path=fpath,
                    reason=f"Failed to compute Merkle tree: {exc}",
                    stage="merkle_root",
                ))
                continue

            # Stage 3: Assemble file and run lightweight health checks
            dest_file = workdir / f"test_{idx}_{Path(fpath).name}"
            try:
                with open(dest_file, "wb") as out_f:
                    for cdata in chunk_data_list:
                        out_f.write(cdata)

                is_healthy, reason = check_file_health(dest_file)
                if not is_healthy:
                    failures.append(RestoreTestFailure(
                        path=fpath,
                        reason=reason,
                        stage="type_check",
                    ))
                else:
                    passed_count += 1
            except Exception as exc:
                failures.append(RestoreTestFailure(
                    path=fpath,
                    reason=f"File assembly or test error: {exc}",
                    stage="type_check",
                ))
            finally:
                # Remove individual restored test file promptly
                if dest_file.exists():
                    try:
                        dest_file.unlink()
                    except OSError:
                        pass

    finally:
        # Guarantee workdir cleanup (even on error, cancel, or test completion)
        if is_temp_workdir:
            try:
                temp_dir_obj.cleanup()
            except Exception:
                pass
        elif workdir.exists():
            try:
                shutil.rmtree(workdir, ignore_errors=True)
            except Exception:
                pass

    if status != "cancelled":
        status = "failed" if len(failures) > 0 else "passed"

    duration = time.time() - start_time
    result = RestoreTestResult(
        backup_id=backup_id,
        status=status,
        sample_count=len(sampled),
        passed_count=passed_count,
        failed_count=len(failures),
        failures=failures,
        duration_seconds=round(duration, 3),
        workdir=str(workdir),
    )

    # 4. Write results to witness DB (migration v3)
    if witness_db is not None:
        try:
            details_json = json.dumps({
                "duration_seconds": result.duration_seconds,
                "passed_count": result.passed_count,
                "failed_count": result.failed_count,
                "failures": [asdict(f) for f in result.failures],
            })
            witness_db.record_restore_test(
                backup_id=backup_id,
                status=result.status,
                sample_count=result.sample_count,
                failed_count=result.failed_count,
                details_json=details_json,
            )
        except Exception as exc:
            logger.error("Failed to record restore test in witness DB: %s", exc)

    return result
