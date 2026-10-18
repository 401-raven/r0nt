"""CLI entry point to execute attack evaluation and generate eval/results.json."""

from __future__ import annotations

import json
import sys
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT / "src"))
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from eval.attacks import run_all_scenarios


def main() -> int:
    print("=" * 80)
    print("                      r0nt ATTACK EVALUATION SUITE")
    print("=" * 80)
    print("Executing attack scenarios against threat model...")

    results = run_all_scenarios()

    out_path = PROJECT_ROOT / "eval" / "results.json"
    out_path.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"\n[OK] Results written to {out_path}")

    print("\n" + "=" * 80)
    print(f"{'ID':<10} {'Threat Capability':<32} {'Detected':<10} {'Duration':<10} {'Finding'}")
    print("-" * 80)
    for s in results["scenarios"]:
        det_str = "YES" if s["detected"] else ("N/A" if s["findings"] == ["out_of_scope"] else "NO")
        findings_str = ", ".join(s["findings"]) if s["findings"] else "none"
        print(f"{s['scenario_id']:<10} {s['threat_capability']:<32} {det_str:<10} {s['duration_ms']:>6.1f}ms   {findings_str}")
    print("=" * 80)

    fp = results["false_positives"]
    print(f"\nFalse Positives: {fp['false_positive_findings']} in {fp['cycles_tested']} clean cycles ({fp['false_positive_rate']*100:.1f}%)")
    print(f"In-scope scenarios caught: {results['in_scope_detected']}/{results['in_scope_scenarios']}")
    print("=" * 80)

    return 0


if __name__ == "__main__":
    sys.exit(main())
