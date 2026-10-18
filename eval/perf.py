"""Performance benchmark harness for r0nt (SPEC_PHASE3 §4, T-61).

Measures:
  1. Backup throughput (MB/s) and time for initial and incremental runs.
  2. Verification throughput (MB/s) and time across modes: quick, sample (10%), and full.
  3. Storage overhead: raw source bytes vs repository (chunks + manifests) + witness DB bytes.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import tempfile
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

# Ensure r0nt is importable
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT / "src"))

from r0nt.chunker import scan_source
from r0nt.manifest import build_manifest, manifest_hash
from r0nt.signing import derive_witness_key, generate_keypair
from r0nt.store import ChunkStore, ManifestStore, WitnessDB
from r0nt.verify import verify_with_stats


@dataclass
class ModePerf:
    mode: str
    duration_s: float
    throughput_mb_s: float
    chunks_checked: int


@dataclass
class BenchmarkRun:
    dataset_size_mb: float
    file_count: int
    source_bytes: int
    repo_bytes: int
    chunks_bytes: int
    manifests_bytes: int
    witness_bytes: int
    overhead_ratio: float
    backup_initial_s: float
    backup_initial_mb_s: float
    backup_incremental_s: float
    backup_incremental_mb_s: float
    dedup_ratio: float
    verify_quick: ModePerf
    verify_sample_10: ModePerf
    verify_full: ModePerf


def _generate_dataset(dest_dir: Path, target_mb: float) -> tuple[int, int]:
    """Populate dest_dir with a mixture of text, repeated data, and binary files."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    target_bytes = int(target_mb * 1024 * 1024)
    written_bytes = 0
    file_idx = 0

    chunk_sample = b"Tamper-evident backup chunk verification payload 0123456789 ABCDEF\n" * 1024  # 68KB

    while written_bytes < target_bytes:
        file_idx += 1
        # Variety of file sizes: small text (10KB), medium (250KB), large (1MB)
        category = file_idx % 3
        if category == 0:
            size = min(10 * 1024, target_bytes - written_bytes)
            data = (f"Text file header #{file_idx}\n".encode() * 50)[:size]
            filename = f"docs/file_{file_idx}.txt"
        elif category == 1:
            size = min(250 * 1024, target_bytes - written_bytes)
            # Semi-repetitive data to exercise chunking deduplication
            data = (chunk_sample * (size // len(chunk_sample) + 1))[:size]
            filename = f"data/record_{file_idx}.dat"
        else:
            size = min(1024 * 1024, target_bytes - written_bytes)
            data = os.urandom(size)
            filename = f"media/blob_{file_idx}.bin"

        fp = dest_dir / filename
        fp.parent.mkdir(parents=True, exist_ok=True)
        fp.write_bytes(data)
        written_bytes += len(data)

    return file_idx, written_bytes


def _dir_size(path: Path) -> int:
    """Calculate total size of all files under path."""
    if not path.exists():
        return 0
    return sum(f.stat().st_size for f in path.rglob("*") if f.is_file())


def measure_performance(size_mb: float = 100.0) -> BenchmarkRun:
    """Run full benchmark for a given dataset size."""
    with tempfile.TemporaryDirectory(prefix=f"r0nt_perf_{int(size_mb)}mb_") as td:
        base = Path(td)
        src_dir = base / "source"
        repo_dir = base / "repo"
        witness_path = base / "witness.sqlite"

        # 1. Generate dataset
        file_count, total_bytes = _generate_dataset(src_dir, size_mb)
        actual_mb = total_bytes / (1024.0 * 1024.0)

        priv_key, pub_key = generate_keypair()
        witness_key = derive_witness_key(pub_key)
        witness_db = WitnessDB(witness_path, witness_key)
        chunk_store = ChunkStore(repo_dir)
        manifest_store = ManifestStore(repo_dir)

        # 2. Initial Backup Benchmark
        t_b0 = time.perf_counter()
        file_results, skipped = scan_source(src_dir)
        new_chunks = 0
        for fr in file_results:
            for c in fr.chunks:
                if chunk_store.write_chunk(c.hash, c.data):
                    new_chunks += 1

        m1 = build_manifest(
            file_results=file_results,
            skipped_files=skipped,
            chunk_size=65536,
            prev_manifest_hash=None,
            sequence_number=1,
            private_key=priv_key,
            public_key=pub_key,
        )
        manifest_store.write_manifest(m1)
        witness_db.record_manifest(m1)
        backup_init_s = time.perf_counter() - t_b0
        backup_init_mb_s = actual_mb / backup_init_s if backup_init_s > 0 else 0.0

        # 3. Incremental Backup Benchmark (modify 5% of files)
        mod_file = src_dir / "docs" / "file_1.txt"
        if mod_file.exists():
            mod_file.write_bytes(b"Modified content for incremental backup test.")

        t_b1 = time.perf_counter()
        file_results_inc, skipped_inc = scan_source(src_dir)
        inc_new_chunks = 0
        for fr in file_results_inc:
            for c in fr.chunks:
                if chunk_store.write_chunk(c.hash, c.data):
                    inc_new_chunks += 1

        m2 = build_manifest(
            file_results=file_results_inc,
            skipped_files=skipped_inc,
            chunk_size=65536,
            prev_manifest_hash=manifest_hash(m1),
            sequence_number=2,
            private_key=priv_key,
            public_key=pub_key,
        )
        manifest_store.write_manifest(m2)
        witness_db.record_manifest(m2)
        backup_inc_s = time.perf_counter() - t_b1
        backup_inc_mb_s = actual_mb / backup_inc_s if backup_inc_s > 0 else 0.0

        # Storage sizes
        chunks_bytes = _dir_size(repo_dir / "chunks")
        manifests_bytes = _dir_size(repo_dir / "manifests")
        repo_bytes = chunks_bytes + manifests_bytes
        witness_bytes = witness_path.stat().st_size if witness_path.exists() else 0
        overhead_ratio = repo_bytes / total_bytes if total_bytes > 0 else 1.0
        dedup_ratio = (total_bytes * 2.0) / chunks_bytes if chunks_bytes > 0 else 1.0

        # 4. Verify Quick Mode
        t_vq = time.perf_counter()
        findings_q, stats_q = verify_with_stats(repo_dir, None, pub_key, witness_db, mode="quick")
        verify_q_s = time.perf_counter() - t_vq
        verify_q_mb_s = actual_mb / verify_q_s if verify_q_s > 0 else 0.0
        q_perf = ModePerf(
            mode="quick",
            duration_s=round(verify_q_s, 4),
            throughput_mb_s=round(verify_q_mb_s, 2),
            chunks_checked=stats_q.get("checked_chunks", 0),
        )

        # 5. Verify Sample Mode (10%)
        t_vs = time.perf_counter()
        findings_s, stats_s = verify_with_stats(
            repo_dir, None, pub_key, witness_db, mode="sample", sample_percent=10.0
        )
        verify_s_s = time.perf_counter() - t_vs
        verify_s_mb_s = actual_mb / verify_s_s if verify_s_s > 0 else 0.0
        s_perf = ModePerf(
            mode="sample (10%)",
            duration_s=round(verify_s_s, 4),
            throughput_mb_s=round(verify_s_mb_s, 2),
            chunks_checked=stats_s.get("checked_chunks", 0),
        )

        # 6. Verify Full Mode
        t_vf = time.perf_counter()
        findings_f, stats_f = verify_with_stats(repo_dir, None, pub_key, witness_db, mode="full")
        verify_f_s = time.perf_counter() - t_vf
        verify_f_mb_s = actual_mb / verify_f_s if verify_f_s > 0 else 0.0
        f_perf = ModePerf(
            mode="full",
            duration_s=round(verify_f_s, 4),
            throughput_mb_s=round(verify_f_mb_s, 2),
            chunks_checked=stats_f.get("checked_chunks", 0),
        )

        witness_db.close()

    return BenchmarkRun(
        dataset_size_mb=round(actual_mb, 2),
        file_count=file_count,
        source_bytes=total_bytes,
        repo_bytes=repo_bytes,
        chunks_bytes=chunks_bytes,
        manifests_bytes=manifests_bytes,
        witness_bytes=witness_bytes,
        overhead_ratio=round(overhead_ratio, 4),
        backup_initial_s=round(backup_init_s, 4),
        backup_initial_mb_s=round(backup_init_mb_s, 2),
        backup_incremental_s=round(backup_inc_s, 4),
        backup_incremental_mb_s=round(backup_inc_mb_s, 2),
        dedup_ratio=round(dedup_ratio, 2),
        verify_quick=q_perf,
        verify_sample_10=s_perf,
        verify_full=f_perf,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="r0nt performance benchmark harness")
    parser.add_argument("--sizes", nargs="+", type=float, default=[10.0, 100.0],
                        help="Dataset sizes in MB to benchmark (default: 10 100)")
    parser.add_argument("--1gb", dest="include_1gb", action="store_true",
                        help="Include 1 GB benchmark run (may take ~1-2 min)")
    args = parser.parse_args()

    sizes = list(args.sizes)
    if args.include_1gb and 1000.0 not in sizes:
        sizes.append(1000.0)

    print("=" * 80)
    print("                    r0nt PERFORMANCE BENCHMARK HARNESS")
    print("=" * 80)

    all_results = []
    for sz in sizes:
        print(f"\n[+] Running benchmark for {sz:.0f} MB dataset...")
        run = measure_performance(sz)
        all_results.append(asdict(run))

        print(f"    Source:      {run.dataset_size_mb} MB across {run.file_count} files")
        print(f"    Repo Size:   {run.repo_bytes / (1024*1024):.2f} MB (overhead: {run.overhead_ratio:.2f}x, dedup: {run.dedup_ratio:.2f}x)")
        print(f"    Backup:      Initial {run.backup_initial_s:.2f}s ({run.backup_initial_mb_s:.1f} MB/s) | Incr {run.backup_incremental_s:.2f}s ({run.backup_incremental_mb_s:.1f} MB/s)")
        print(f"    Verify Quick:  {run.verify_quick.duration_s:.3f}s ({run.verify_quick.throughput_mb_s:.1f} MB/s)")
        print(f"    Verify Sample: {run.verify_sample_10.duration_s:.3f}s ({run.verify_sample_10.throughput_mb_s:.1f} MB/s)")
        print(f"    Verify Full:   {run.verify_full.duration_s:.3f}s ({run.verify_full.throughput_mb_s:.1f} MB/s)")

    out_path = PROJECT_ROOT / "eval" / "perf_results.json"
    out_path.write_text(json.dumps({"benchmarks": all_results}, indent=2), encoding="utf-8")
    print(f"\n[OK] Benchmark results written to {out_path}")
    print("=" * 80)
    return 0


if __name__ == "__main__":
    sys.exit(main())
