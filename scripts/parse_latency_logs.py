#!/usr/bin/env python3
"""Parse audit logs for thesis-ready latency analysis.

Reads decisions.jsonl and optionally operations.jsonl, correlates entries
by request_id, and produces percentile-based latency statistics with
per-decision-type breakdowns.

Log file locations (macOS):
    ~/Library/Logs/mcp-acp/proxies/<proxy_name>/audit/decisions.jsonl
    ~/Library/Logs/mcp-acp/proxies/<proxy_name>/audit/operations.jsonl

Usage:
    python scripts/parse_latency_logs.py <decisions.jsonl> [operations.jsonl]
    python scripts/parse_latency_logs.py <decisions.jsonl> [operations.jsonl] --date 2025-01-15
    python scripts/parse_latency_logs.py <decisions.jsonl> [operations.jsonl] --by-decision
    python scripts/parse_latency_logs.py <decisions.jsonl> [operations.jsonl] --output log_parse_results.json
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from statistics import mean, quantiles, stdev


@dataclass
class MetricStats:
    """Aggregated latency statistics with percentiles."""

    n: int
    median_ms: float
    mean_ms: float
    stdev_ms: float
    min_ms: float
    max_ms: float
    p25_ms: float
    p50_ms: float
    p75_ms: float
    p95_ms: float
    p99_ms: float


def _compute_stats(values: list[float]) -> MetricStats:
    """Compute descriptive statistics with percentiles.

    Uses ``statistics.quantiles(n=100)`` for percentile calculation.
    Falls back gracefully for n < 2.
    """
    if not values:
        return MetricStats(
            n=0,
            median_ms=0.0,
            mean_ms=0.0,
            stdev_ms=0.0,
            min_ms=0.0,
            max_ms=0.0,
            p25_ms=0.0,
            p50_ms=0.0,
            p75_ms=0.0,
            p95_ms=0.0,
            p99_ms=0.0,
        )

    if len(values) == 1:
        v = round(values[0], 2)
        return MetricStats(
            n=1,
            median_ms=v,
            mean_ms=v,
            stdev_ms=0.0,
            min_ms=v,
            max_ms=v,
            p25_ms=v,
            p50_ms=v,
            p75_ms=v,
            p95_ms=v,
            p99_ms=v,
        )

    pcts = quantiles(values, n=100)
    return MetricStats(
        n=len(values),
        median_ms=round(pcts[49], 2),
        mean_ms=round(mean(values), 2),
        stdev_ms=round(stdev(values), 2),
        min_ms=round(min(values), 2),
        max_ms=round(max(values), 2),
        p25_ms=round(pcts[24], 2),
        p50_ms=round(pcts[49], 2),
        p75_ms=round(pcts[74], 2),
        p95_ms=round(pcts[94], 2),
        p99_ms=round(pcts[98], 2),
    )


def parse_decisions(
    path: Path,
    date_filter: str | None = None,
) -> list[dict]:
    """Parse decisions.jsonl and return raw decision entries.

    Each returned dict contains the fields needed for analysis:
    ``request_id``, ``decision``, ``policy_eval_ms``, ``policy_hitl_ms``,
    ``policy_total_ms``, ``tool_name``, ``mcp_method``.
    """
    entries: list[dict] = []
    skipped = 0

    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                raw = json.loads(line)
            except json.JSONDecodeError:
                skipped += 1
                continue

            if raw.get("event") != "policy_decision":
                continue

            if date_filter and not raw.get("time", "").startswith(date_filter):
                continue

            entries.append(
                {
                    "request_id": raw.get("request_id"),
                    "decision": raw.get("decision"),
                    "policy_eval_ms": raw.get("policy_eval_ms"),
                    "policy_hitl_ms": raw.get("policy_hitl_ms"),
                    "policy_total_ms": raw.get("policy_total_ms"),
                    "tool_name": raw.get("tool_name"),
                    "mcp_method": raw.get("mcp_method"),
                }
            )

    if skipped:
        print(f"Warning: skipped {skipped} malformed lines in {path}", file=sys.stderr)

    return entries


def parse_operations(
    path: Path,
    date_filter: str | None = None,
) -> dict[str, float]:
    """Parse operations.jsonl and return ``{request_id: duration_ms}``.

    The duration is extracted from the nested ``duration.duration_ms`` field.
    """
    ops: dict[str, float] = {}
    skipped = 0

    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                raw = json.loads(line)
            except json.JSONDecodeError:
                skipped += 1
                continue

            if date_filter and not raw.get("time", "").startswith(date_filter):
                continue

            request_id = raw.get("request_id")
            duration = raw.get("duration")
            if request_id is not None and isinstance(duration, dict):
                dur_ms = duration.get("duration_ms")
                if dur_ms is not None:
                    ops[str(request_id)] = dur_ms

    if skipped:
        print(f"Warning: skipped {skipped} malformed lines in {path}", file=sys.stderr)

    return ops


def correlate(
    decisions: list[dict],
    operations: dict[str, float],
) -> list[dict]:
    """Join decisions with operations by request_id and derive backend_ms.

    Each correlated entry gains ``duration_ms`` and ``backend_ms`` fields.
    ``backend_ms = duration_ms - policy_total_ms`` (clamped to 0).
    """
    correlated: list[dict] = []
    for dec in decisions:
        rid = str(dec["request_id"]) if dec["request_id"] is not None else None
        if rid is None or rid not in operations:
            continue
        entry = dict(dec)
        entry["duration_ms"] = operations[rid]
        total = dec.get("policy_total_ms") or 0.0
        entry["backend_ms"] = max(0.0, operations[rid] - total)
        correlated.append(entry)
    return correlated


def group_by_decision(
    entries: list[dict],
) -> dict[str, list[dict]]:
    """Split entries by decision type (allow / deny / hitl)."""
    groups: dict[str, list[dict]] = {}
    for entry in entries:
        key = (entry.get("decision") or "unknown").lower()
        groups.setdefault(key, []).append(entry)
    return groups


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------


def _fmt_stat_line(stats: MetricStats, label: str) -> str:
    """Format a single metric block for the text report."""
    if stats.n == 0:
        return f"--- {label} ---\n  No samples found.\n"

    lines = [
        f"--- {label} ---",
        f"  n={stats.n}  median={stats.median_ms:.2f}ms  mean={stats.mean_ms:.2f}ms  stdev={stats.stdev_ms:.2f}ms",
        f"  p25={stats.p25_ms:.2f}  p50={stats.p50_ms:.2f}  p75={stats.p75_ms:.2f}  p95={stats.p95_ms:.2f}  p99={stats.p99_ms:.2f}",
        f"  min={stats.min_ms:.2f}  max={stats.max_ms:.2f}",
    ]
    return "\n".join(lines) + "\n"


def _extract(entries: list[dict], key: str) -> list[float]:
    """Extract non-None float values for *key* from a list of dicts."""
    return [e[key] for e in entries if e.get(key) is not None]


def print_report(
    *,
    decisions: list[dict],
    correlated: list[dict],
    decisions_path: Path,
    operations_path: Path | None,
    date_filter: str | None,
    by_decision: bool,
) -> None:
    """Print the full text report to stdout."""
    print("=" * 60)
    print("Latency Analysis Report")
    print("=" * 60)

    files = str(decisions_path)
    if operations_path:
        files += f", {operations_path}"
    print(f"Log files: {files}")
    print(f"Date filter: {date_filter or 'none'}")
    print(
        f"Entries: {len(decisions)} decisions"
        + (f", {len(correlated)} correlated operations" if operations_path else "")
    )
    print()

    # Policy eval
    eval_stats = _compute_stats(_extract(decisions, "policy_eval_ms"))
    print(_fmt_stat_line(eval_stats, "Policy Evaluation (policy_eval_ms)"))

    # HITL wait
    hitl_stats = _compute_stats(_extract(decisions, "policy_hitl_ms"))
    print(_fmt_stat_line(hitl_stats, "HITL Wait (policy_hitl_ms)"))

    # Policy total
    total_stats = _compute_stats(_extract(decisions, "policy_total_ms"))
    print(_fmt_stat_line(total_stats, "Policy Total (policy_total_ms)"))

    # End-to-end proxy (from operations)
    if correlated:
        e2e_stats = _compute_stats(_extract(correlated, "duration_ms"))
        print(_fmt_stat_line(e2e_stats, "End-to-End Proxy (duration_ms, from operations.jsonl)"))

        backend_stats = _compute_stats(_extract(correlated, "backend_ms"))
        print(_fmt_stat_line(backend_stats, "Backend Call (derived: duration - policy_total)"))

    # Excluding-HITL stats (if any HITL entries exist)
    non_hitl_decisions = [d for d in decisions if (d.get("decision") or "").lower() != "hitl"]
    non_hitl_correlated = [c for c in correlated if (c.get("decision") or "").lower() != "hitl"]
    if len(non_hitl_decisions) < len(decisions):
        print(f"--- Excluding HITL ({len(decisions) - len(non_hitl_decisions)} entries removed) ---\n")
        nh_eval = _compute_stats(_extract(non_hitl_decisions, "policy_eval_ms"))
        print(_fmt_stat_line(nh_eval, "Policy Evaluation excl. HITL"))
        nh_total = _compute_stats(_extract(non_hitl_decisions, "policy_total_ms"))
        print(_fmt_stat_line(nh_total, "Policy Total excl. HITL"))
        if non_hitl_correlated:
            nh_e2e = _compute_stats(_extract(non_hitl_correlated, "duration_ms"))
            print(_fmt_stat_line(nh_e2e, "End-to-End Proxy excl. HITL"))
            nh_backend = _compute_stats(_extract(non_hitl_correlated, "backend_ms"))
            print(_fmt_stat_line(nh_backend, "Backend Call excl. HITL"))

    # Per-decision breakdown
    if by_decision:
        source = correlated if correlated else decisions
        groups = group_by_decision(source)
        print("--- By Decision Type ---")
        for dtype in ("allow", "deny", "hitl"):
            group = groups.get(dtype, [])
            if not group:
                continue
            eval_s = _compute_stats(_extract(group, "policy_eval_ms"))
            label = f"  {dtype.upper():5s} (n={len(group)}):"
            parts = [f"eval p50={eval_s.p50_ms:.2f}ms"]

            hitl_vals = _extract(group, "policy_hitl_ms")
            if hitl_vals:
                hitl_s = _compute_stats(hitl_vals)
                parts.append(f"hitl p50={hitl_s.p50_ms:.0f}ms")

            e2e_vals = _extract(group, "duration_ms")
            if e2e_vals:
                e2e_s = _compute_stats(e2e_vals)
                parts.append(f"e2e p50={e2e_s.p50_ms:.2f}ms")

            print(f"{label}  {'  '.join(parts)}")

        # Show unknown decisions if present
        for dtype, group in sorted(groups.items()):
            if dtype in ("allow", "deny", "hitl"):
                continue
            eval_s = _compute_stats(_extract(group, "policy_eval_ms"))
            print(f"  {dtype.upper():5s} (n={len(group)}):  eval p50={eval_s.p50_ms:.2f}ms")

        print()


def build_json_output(
    *,
    decisions: list[dict],
    correlated: list[dict],
    decisions_path: Path,
    operations_path: Path | None,
    date_filter: str | None,
    by_decision: bool,
) -> dict:
    """Build the machine-readable JSON output dict."""
    result: dict = {
        "decisions_path": str(decisions_path),
        "operations_path": str(operations_path) if operations_path else None,
        "date_filter": date_filter,
        "decision_count": len(decisions),
        "correlated_count": len(correlated),
        "policy_eval": asdict(_compute_stats(_extract(decisions, "policy_eval_ms"))),
        "hitl_wait": asdict(_compute_stats(_extract(decisions, "policy_hitl_ms"))),
        "policy_total": asdict(_compute_stats(_extract(decisions, "policy_total_ms"))),
    }

    if correlated:
        result["end_to_end"] = asdict(_compute_stats(_extract(correlated, "duration_ms")))
        result["backend_call"] = asdict(_compute_stats(_extract(correlated, "backend_ms")))

    # Excluding-HITL stats
    non_hitl_decisions = [d for d in decisions if (d.get("decision") or "").lower() != "hitl"]
    non_hitl_correlated = [c for c in correlated if (c.get("decision") or "").lower() != "hitl"]
    if len(non_hitl_decisions) < len(decisions):
        excl: dict = {
            "hitl_entries_removed": len(decisions) - len(non_hitl_decisions),
            "decision_count": len(non_hitl_decisions),
            "policy_eval": asdict(_compute_stats(_extract(non_hitl_decisions, "policy_eval_ms"))),
            "policy_total": asdict(_compute_stats(_extract(non_hitl_decisions, "policy_total_ms"))),
        }
        if non_hitl_correlated:
            excl["correlated_count"] = len(non_hitl_correlated)
            excl["end_to_end"] = asdict(_compute_stats(_extract(non_hitl_correlated, "duration_ms")))
            excl["backend_call"] = asdict(_compute_stats(_extract(non_hitl_correlated, "backend_ms")))
        result["excluding_hitl"] = excl

    if by_decision:
        source = correlated if correlated else decisions
        groups = group_by_decision(source)
        by_dec: dict[str, dict] = {}
        for dtype, group in sorted(groups.items()):
            entry: dict = {
                "n": len(group),
                "policy_eval": asdict(_compute_stats(_extract(group, "policy_eval_ms"))),
            }
            hitl_vals = _extract(group, "policy_hitl_ms")
            if hitl_vals:
                entry["hitl_wait"] = asdict(_compute_stats(hitl_vals))
            e2e_vals = _extract(group, "duration_ms")
            if e2e_vals:
                entry["end_to_end"] = asdict(_compute_stats(e2e_vals))
                entry["backend_call"] = asdict(_compute_stats(_extract(group, "backend_ms")))
            by_dec[dtype] = entry
        result["by_decision"] = by_dec

    return result


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Parse audit logs for latency analysis with percentiles.",
        epilog=(
            "Log file locations (macOS):\n"
            "  ~/Library/Logs/mcp-acp/proxies/<proxy_name>/audit/decisions.jsonl\n"
            "  ~/Library/Logs/mcp-acp/proxies/<proxy_name>/audit/operations.jsonl"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "decisions_path",
        type=Path,
        help="Path to decisions.jsonl file",
    )
    parser.add_argument(
        "operations_path",
        nargs="?",
        type=Path,
        default=None,
        help="Path to operations.jsonl file (optional, enables correlation)",
    )
    parser.add_argument(
        "--date",
        type=str,
        default=None,
        help="Filter entries by ISO date prefix (e.g. 2025-01-15)",
    )
    parser.add_argument(
        "--by-decision",
        action="store_true",
        default=False,
        help="Group statistics by decision type (allow/deny/hitl)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Save machine-readable results as JSON to this path",
    )
    args = parser.parse_args()

    if not args.decisions_path.exists():
        print(f"Error: decisions log not found: {args.decisions_path}", file=sys.stderr)
        sys.exit(1)

    if args.operations_path and not args.operations_path.exists():
        print(f"Error: operations log not found: {args.operations_path}", file=sys.stderr)
        sys.exit(1)

    # Parse logs
    decisions = parse_decisions(args.decisions_path, args.date)

    operations: dict[str, float] = {}
    if args.operations_path:
        operations = parse_operations(args.operations_path, args.date)

    correlated = correlate(decisions, operations) if operations else []

    # Text report
    print_report(
        decisions=decisions,
        correlated=correlated,
        decisions_path=args.decisions_path,
        operations_path=args.operations_path,
        date_filter=args.date,
        by_decision=args.by_decision,
    )

    # JSON output
    if args.output:
        result = build_json_output(
            decisions=decisions,
            correlated=correlated,
            decisions_path=args.decisions_path,
            operations_path=args.operations_path,
            date_filter=args.date,
            by_decision=args.by_decision,
        )
        args.output.write_text(json.dumps(result, indent=2) + "\n")
        print(f"\nResults saved to {args.output}")


if __name__ == "__main__":
    main()
