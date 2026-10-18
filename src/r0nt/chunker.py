"""Split files into fixed-size chunks and hash them.

Handles path canonicalization, TOCTOU detection, guard limits,
and non-regular file classification per SPEC §1.
"""

from __future__ import annotations

import hashlib
import os
import stat
import unicodedata
from pathlib import Path
from typing import NamedTuple

DEFAULT_CHUNK_SIZE = 1024 * 1024  # 1 MiB
DEFAULT_MAX_FILE_SIZE = 10 * 1024 * 1024 * 1024  # 10 GiB
DEFAULT_MAX_TOTAL_SIZE = 100 * 1024 * 1024 * 1024  # 100 GiB
DEFAULT_MAX_FILE_COUNT = 1_000_000
MAX_TOCTOU_RETRIES = 2


class ChunkInfo(NamedTuple):
    """A single chunk produced during file reading."""
    hash: str   # lowercase hex SHA-256
    data: bytes


class FileResult(NamedTuple):
    """Result of chunking a single regular file."""
    path: str              # canonical relative path
    size: int              # bytes
    mtime: int             # Unix epoch seconds (truncated)
    chunks: list[ChunkInfo]
    unstable: bool         # True if file changed during chunking


class SkippedFile(NamedTuple):
    """A file that was skipped during backup."""
    path: str
    reason: str
    type: str              # symlink | special | unreadable | too_large | path_traversal
    target: str | None     # symlink target, if applicable


# ---------------------------------------------------------------------------
# Hashing
# ---------------------------------------------------------------------------

def hash_chunk(data: bytes) -> str:
    """SHA-256 of raw chunk bytes, returned as lowercase hex."""
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# Path canonicalization  (SPEC §2 — Path canonicalization)
# ---------------------------------------------------------------------------

def canonicalize_path(filepath: Path, source_root: Path) -> str:
    """Convert a filesystem path to a canonical relative path.

    Rules:
      - Relative to *source_root*, no leading '/'.
      - Forward-slash separator, even on Windows.
      - '..' components are forbidden (raises ValueError).
      - NFC-normalized Unicode.
    """
    if '..' in filepath.parts:
        raise ValueError(f"Path traversal ('..') in path: {filepath}")

    try:
        rel = filepath.resolve().relative_to(source_root.resolve())
    except ValueError as exc:
        raise ValueError(f"Path traversal ('..') or path outside source root: {filepath}") from exc

    parts = rel.parts
    for part in parts:
        if part == '..':
            raise ValueError(f"Path traversal ('..') in path: {rel}")
    canonical = '/'.join(parts)
    canonical = unicodedata.normalize('NFC', canonical)
    return canonical


# ---------------------------------------------------------------------------
# File classification helpers
# ---------------------------------------------------------------------------

def _stat_file(filepath: Path) -> tuple[int, int]:
    """Return (size, mtime_seconds) — mtime truncated to integer."""
    st = filepath.stat()
    return st.st_size, int(st.st_mtime)


def _is_symlink_or_junction(filepath: Path) -> bool:
    """True for symlinks and Windows junctions / reparse points."""
    return filepath.is_symlink()


def _is_special_file(filepath: Path) -> bool:
    """True for pipes, device files, sockets."""
    try:
        mode = filepath.lstat().st_mode
        return (
            stat.S_ISFIFO(mode)
            or stat.S_ISCHR(mode)
            or stat.S_ISBLK(mode)
            or stat.S_ISSOCK(mode)
        )
    except (OSError, AttributeError):
        return False


# ---------------------------------------------------------------------------
# Core chunking
# ---------------------------------------------------------------------------

def chunk_file(
    filepath: Path,
    source_root: Path,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> FileResult:
    """Read *filepath* in fixed-size chunks, applying TOCTOU detection.

    After reading all chunks the file is re-stat'd.  If size or mtime
    changed the file is re-read (up to ``MAX_TOCTOU_RETRIES`` times).
    If the file is still changing it is flagged ``unstable``.
    """
    canonical = canonicalize_path(filepath, source_root)

    post_size = post_mtime = 0
    chunks: list[ChunkInfo] = []

    for _attempt in range(MAX_TOCTOU_RETRIES + 1):
        pre_size, pre_mtime = _stat_file(filepath)

        chunks = []
        with open(filepath, 'rb') as fh:
            while True:
                data = fh.read(chunk_size)
                if not data:
                    break
                chunks.append(ChunkInfo(hash=hash_chunk(data), data=data))

        post_size, post_mtime = _stat_file(filepath)

        if pre_size == post_size and pre_mtime == post_mtime:
            return FileResult(
                path=canonical,
                size=post_size,
                mtime=post_mtime,
                chunks=chunks,
                unstable=False,
            )

    # Exhausted retries — mark unstable
    return FileResult(
        path=canonical,
        size=post_size,
        mtime=post_mtime,
        chunks=chunks,
        unstable=True,
    )


# ---------------------------------------------------------------------------
# Directory scanning
# ---------------------------------------------------------------------------

def scan_sources(
    sources: list[tuple[str, Path]],
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
    max_total_size: int = DEFAULT_MAX_TOTAL_SIZE,
    max_file_count: int = DEFAULT_MAX_FILE_COUNT,
    exclude_matcher: Any = None,
    progress_callback: Any = None,
    cancel_event: Any = None,
) -> tuple[list[FileResult], list[SkippedFile]]:
    """Walk one or more labeled sources, applying exclude patterns and guard limits.

    sources is a list of (label, path).
    If label is non-empty, canonical paths become '{label}/{relative_path}'.
    """
    seen_labels: set[str] = set()
    for label, _ in sources:
        if label:
            if label in seen_labels:
                raise ValueError(f"Duplicate source label: '{label}'")
            seen_labels.add(label)

    results: list[FileResult] = []
    skipped: list[SkippedFile] = []
    total_size = 0
    file_count = 0
    seen_lower: dict[str, str] = {}

    for label, source_root in sources:
        source_root = Path(source_root).resolve()
        if not source_root.exists() or not source_root.is_dir():
            continue

        for dirpath, _dirnames, filenames in os.walk(source_root, followlinks=False):
            if cancel_event and cancel_event.is_set():
                break

            for name in sorted(filenames):
                if cancel_event and cancel_event.is_set():
                    break

                filepath = Path(dirpath) / name

                # --- canonical path ---
                try:
                    rel_canonical = canonicalize_path(filepath, source_root)
                except ValueError as exc:
                    skipped.append(SkippedFile(
                        path=str(filepath.relative_to(source_root)),
                        reason=str(exc),
                        type='path_traversal',
                        target=None,
                    ))
                    continue

                canonical = f"{label}/{rel_canonical}" if label else rel_canonical

                # --- exclude check (SPEC_PHASE2 §2: excluded files never appear in manifest) ---
                if exclude_matcher and exclude_matcher.matches(canonical):
                    continue

                # --- case collision ---
                lower = canonical.lower()
                if lower in seen_lower:
                    raise ValueError(
                        f"Case collision: '{canonical}' and '{seen_lower[lower]}' "
                        f"resolve to the same path on case-insensitive filesystems."
                    )
                seen_lower[lower] = canonical

                # --- symlink / junction ---
                if _is_symlink_or_junction(filepath):
                    try:
                        target = str(os.readlink(filepath))
                    except OSError:
                        target = '<unreadable>'
                    skipped.append(SkippedFile(
                        path=canonical, reason='symlink',
                        type='symlink', target=target,
                    ))
                    continue

                # --- special file ---
                if _is_special_file(filepath):
                    skipped.append(SkippedFile(
                        path=canonical,
                        reason='special file (pipe, device, or socket)',
                        type='special', target=None,
                    ))
                    continue

                # --- guard: file count ---
                file_count += 1
                if file_count > max_file_count:
                    raise ValueError(
                        f"File count exceeds limit ({max_file_count}). "
                        f"Override with --max-file-count."
                    )

                # --- guard: individual file size ---
                try:
                    fsize = filepath.stat().st_size
                except OSError as exc:
                    skipped.append(SkippedFile(
                        path=canonical, reason=f'unreadable: {exc}',
                        type='unreadable', target=None,
                    ))
                    continue

                if fsize > max_file_size:
                    skipped.append(SkippedFile(
                        path=canonical,
                        reason=f'file size {fsize} exceeds limit {max_file_size}',
                        type='too_large', target=None,
                    ))
                    continue

                # --- guard: total size ---
                total_size += fsize
                if total_size > max_total_size:
                    raise ValueError(
                        f"Total backup size exceeds limit ({max_total_size} bytes). "
                        f"Override with --max-total-size."
                    )

                # --- chunk the file ---
                try:
                    result = chunk_file(filepath, source_root, chunk_size)
                    # If labeled, adjust result path to canonical
                    if label:
                        result = FileResult(
                            path=canonical,
                            size=result.size,
                            mtime=result.mtime,
                            chunks=result.chunks,
                            unstable=result.unstable,
                        )
                    results.append(result)

                    if progress_callback:
                        progress_callback(
                            current_file=canonical,
                            files_done=len(results),
                            bytes_done=total_size,
                        )
                except OSError as exc:
                    skipped.append(SkippedFile(
                        path=canonical, reason=f'unreadable: {exc}',
                        type='unreadable', target=None,
                    ))

    return results, skipped


def scan_source(
    source_root: Path,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
    max_total_size: int = DEFAULT_MAX_TOTAL_SIZE,
    max_file_count: int = DEFAULT_MAX_FILE_COUNT,
) -> tuple[list[FileResult], list[SkippedFile]]:
    """Walk *source_root* and chunk every regular file.

    Returns ``(file_results, skipped_files)``.
    """
    return scan_sources(
        sources=[("", source_root)],
        chunk_size=chunk_size,
        max_file_size=max_file_size,
        max_total_size=max_total_size,
        max_file_count=max_file_count,
    )

