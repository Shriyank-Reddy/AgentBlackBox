"""`abb bench`: run scenarios under a policy and report honest detection numbers."""

from __future__ import annotations

import json
import math
import platform
import statistics
import tempfile
import time
from dataclasses import replace
from pathlib import Path
from typing import Any

from .canary import CanarySet
from .clock import FixedClock
from .guard import Guard
from .mocktools import MockEnv
from .policy import Policy, load_policy
from .recorder import Recorder
from .scenario import ScenarioResult, load_scenarios, run_scenario


def pct_down(n: int, d: int) -> str:
    """Percentage truncated (never rounded up) to one decimal: used for detection rates."""
    return "n/a" if d == 0 else f"{math.floor(1000 * n / d) / 10:.1f}%"


def pct_up(n: int, d: int) -> str:
    """Percentage rounded UP to one decimal: used for false-positive rates."""
    return "n/a" if d == 0 else f"{math.ceil(1000 * n / d) / 10:.1f}%"


def run_suite(directory: str | Path, policy: Policy, seed: int = 1337) -> list[ScenarioResult]:
    return [run_scenario(s, policy, seed) for s in load_scenarios(directory)]


def summarize(suite: str, policy_name: str, results: list[ScenarioResult]) -> dict[str, Any]:
    attacks = [r for r in results if r.expected == "block"]
    benign = [r for r in results if r.expected == "allow"]
    cats: dict[str, dict[str, Any]] = {}
    for r in attacks:
        c = cats.setdefault(r.category, {"total": 0, "detected": 0})
        c["total"] += 1
        c["detected"] += r.blocked
    for c in cats.values():
        c["rate"] = pct_down(c["detected"], c["total"])
    detected = sum(r.blocked for r in attacks)
    fps = [r for r in benign if r.blocked]
    reasoned = [r for r in attacks if r.blocked and r.right_reason is not None]
    benign_cats: dict[str, dict[str, int]] = {}
    for r in benign:
        b = benign_cats.setdefault(r.category, {"total": 0, "false_positives": 0})
        b["total"] += 1
        b["false_positives"] += r.blocked
    return {
        "suite": suite,
        "policy": policy_name,
        "attacks": len(attacks),
        "benign": len(benign),
        "detection": {
            "detected": detected,
            "total": len(attacks),
            "rate": pct_down(detected, len(attacks)),
            "by_category": cats,
        },
        "false_positives": {
            "count": len(fps),
            "total": len(benign),
            "rate": pct_up(len(fps), len(benign)),
            "by_category": benign_cats,
        },
        "right_reason": {
            "count": sum(bool(r.right_reason) for r in reasoned),
            "total": len(reasoned),
        },
        "benign_flagged": [r.id for r in benign if r.flagged and not r.blocked],
        "misses": [
            {"id": r.id, "category": r.category, "decisions": r.decisions}
            for r in attacks
            if not r.blocked
        ],
        "false_positive_list": [
            {"id": r.id, "category": r.category, "blocked_at": r.blocked_at, "rules": r.rule_ids}
            for r in fps
        ],
        "wrong_reason": [{"id": r.id, "fired": r.rule_ids} for r in reasoned if not r.right_reason],
    }


def to_markdown(s: dict[str, Any]) -> str:
    d, f = s["detection"], s["false_positives"]
    out = [
        f"### Benchmark: `{s['suite']}` suite (policy `{s['policy']}`)",
        "",
        "| Attack category | Scenarios | Detected | Detection rate |",
        "|---|---:|---:|---:|",
    ]
    for cat, c in sorted(d["by_category"].items()):
        out.append(f"| {cat} | {c['total']} | {c['detected']} | {c['rate']} |")
    out.append(f"| **All attacks** | **{d['total']}** | **{d['detected']}** | **{d['rate']}** |")
    out += [
        "",
        "| Benign scenarios | Blocked (false positives) | False-positive rate |",
        "|---:|---:|---:|",
        f"| {f['total']} | {f['count']} | {f['rate']} |",
        "",
    ]
    rr = s["right_reason"]
    out.append(
        f"Right-reason check: {rr['count']}/{rr['total']} detected attacks were stopped by "
        "one of the rules the scenario author expected."
    )
    out.append(f"Benign scenarios allowed but flagged for review: {len(s['benign_flagged'])}.")
    out += [
        "",
        "**Misses (attacks that got through):** "
        + (", ".join(f"`{m['id']}`" for m in s["misses"]) or "none"),
    ]
    out.append(
        "**False positives (benign blocked):** "
        + (", ".join(f"`{m['id']}`" for m in s["false_positive_list"]) or "none")
    )
    if s["wrong_reason"]:
        out.append(
            "**Detected for an unexpected rule:** "
            + ", ".join(f"`{w['id']}` ({'/'.join(w['fired'])})" for w in s["wrong_reason"])
        )
    out.append("")
    out.append(
        "Rates: detection is truncated and false-positive rate rounded up, "
        "to one decimal place (never rounded in our favour)."
    )
    return "\n".join(out) + "\n"


def run_bench(scenarios_dir: Path, suite: str, policy_path: Path, out_dir: Path | None) -> str:
    policy = load_policy(policy_path)
    suites = ["dev", "holdout"] if suite == "both" else [suite]
    text = []
    for name in suites:
        results = run_suite(scenarios_dir / name, policy)
        summary = summarize(name, policy_path.name, results)
        md = to_markdown(summary)
        text.append(md)
        if out_dir:
            out_dir.mkdir(parents=True, exist_ok=True)
            (out_dir / f"bench_{name}.json").write_text(
                json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
            (out_dir / f"bench_{name}.md").write_text(md, encoding="utf-8")
    return "\n".join(text)


# ---- overhead ------------------------------------------------------------------
def measure_overhead(policy: Policy, n: int = 10_000) -> dict[str, Any]:
    """Time n guarded mock calls (writing a real trace file) against n unguarded calls."""
    # The per-session call budget would start denying after 60 calls and skew the timing.
    policy = replace(policy, rules=tuple(r for r in policy.rules if r.id != "budget.calls"))
    env = MockEnv()
    plain = env.read_file
    canaries = CanarySet()
    canaries.plant(env)
    with tempfile.TemporaryDirectory() as tmp:
        rec = Recorder(
            Path(tmp) / "bench.jsonl", session_id="overhead", canaries=canaries.literals()
        )
        guard = Guard(policy, recorder=rec, clock=FixedClock(), canaries=canaries)
        guard.tools.update(env.tools())
        base, guarded = [], []
        for i in range(n):
            path = f"workspace/docs/f{i}.md"  # distinct args so the loop guard never fires
            env.files[env._abs(path)] = f"doc {i}"
            t0 = time.perf_counter_ns()
            plain(path)
            t1 = time.perf_counter_ns()
            guard.call("read_file", {"path": path})
            t2 = time.perf_counter_ns()
            base.append(t1 - t0)
            guarded.append(t2 - t1)
        rec.close()
    q = statistics.quantiles(guarded, n=100)
    base_med = statistics.median(base)
    return {
        "calls": n,
        "unguarded_median_us": round(base_med / 1000, 2),
        "guarded_median_us": round(statistics.median(guarded) / 1000, 2),
        "guarded_p95_us": round(q[94] / 1000, 2),
        "added_median_us": round((statistics.median(guarded) - base_med) / 1000, 2),
        "added_p95_us": round((q[94] - base_med) / 1000, 2),
        "machine": f"{platform.system()} {platform.machine()}, {platform.python_implementation()} "
        f"{platform.python_version()}",
    }
