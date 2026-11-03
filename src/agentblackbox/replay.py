"""Counterfactual replay: re-evaluate a recorded trace under a different policy.

Replay never re-runs tools. It feeds each recorded call, with the taint labels that were
recorded at the time, to the new policy and compares the verdict with the old decision.
Limits (documented in docs/ARCHITECTURE.md): arguments are the *redacted* ones, and taint
labels are taken from the trace rather than recomputed.
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .normalize import NormalizedCall
from .policy import EvalContext, Policy
from .recorder import DEFAULT_HEAD_KEY, canonical_json, read_events, verify_trace
from .secrets import find_secrets

CHANGES = ("newly_denied", "newly_allowed", "flag_changed", "unchanged")


@dataclass
class ReplayRow:
    seq: int
    tool: str
    summary: str
    old: str
    new: str
    old_rules: list[str]
    new_rules: list[str]
    reasons: list[str]
    change: str


@dataclass
class ReplayReport:
    policy_mode: str
    rows: list[ReplayRow] = field(default_factory=list)
    integrity_ok: bool = True
    integrity_note: str = ""

    @property
    def counts(self) -> dict[str, int]:
        c = Counter(r.change for r in self.rows)
        return {k: c.get(k, 0) for k in CHANGES}

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy_mode": self.policy_mode,
            "integrity_ok": self.integrity_ok,
            "counts": self.counts,
            "rows": [asdict(r) for r in self.rows],
        }


def _classify(old: str, new: str) -> str:
    if old == new:
        return "unchanged"
    if new == "deny":
        return "newly_denied"
    if old == "deny":
        return "newly_allowed"
    return "flag_changed"  # allow <-> flag


def _summary(args: dict[str, Any]) -> str:
    for key in ("url", "path", "command", "to", "name"):
        if isinstance(args.get(key), str):
            return f"{key}={args[key][:70]}"
    return json.dumps(args, sort_keys=True)[:70]


def replay_events(events: list[dict[str, Any]], policy: Policy) -> ReplayReport:
    """Re-evaluate the ``call`` events of an already-loaded trace."""
    report = ReplayReport(policy.mode)
    seen: Counter[str] = Counter()
    total = 0
    for ev in events:
        if ev.get("kind") != "call":
            continue
        args = ev.get("args", {})
        key = ev["tool"] + canonical_json(args)  # same key the live guard used
        seen[key] += 1
        total += 1
        norm = NormalizedCall(ev["tool"], args, policy.sandbox_root)
        # A redaction marker of type *canary* means a canary was in the original arguments.
        hits = tuple(
            h.text for _, text in norm.views() for h in find_secrets(text) if "canary" in h.kind
        )[:1]
        taint = ev.get("taint", {})
        ctx = EvalContext(
            tool=ev["tool"],
            norm=norm,
            session_labels=frozenset(taint.get("session", [])),
            call_labels=frozenset(taint.get("call", [])),
            same_call_count=seen[key],
            total_calls=total,
            canary_hits=hits,
        )
        verdict = policy.evaluate(ctx)
        old = ev.get("decision", "allow")
        report.rows.append(
            ReplayRow(
                ev["seq"],
                ev["tool"],
                _summary(args),
                old,
                verdict.decision,
                list(ev.get("rule_ids", [])),
                list(verdict.rule_ids),
                list(verdict.reasons),
                _classify(old, verdict.decision),
            )
        )
    return report


def replay_trace(path: str | Path, policy: Policy, key: bytes = DEFAULT_HEAD_KEY) -> ReplayReport:
    check = verify_trace(path, key=key)
    report = replay_events(read_events(path), policy)
    report.integrity_ok = check.ok
    if not check.ok:
        err = check.errors[0]
        report.integrity_note = f"trace failed verification at seq {err.seq}: {err.reason}"
    return report


def format_report(report: ReplayReport, trace_name: str, policy_name: str) -> str:
    c = report.counts
    lines = [f"Replay of {trace_name} ({len(report.rows)} calls) under {policy_name}"]
    if not report.integrity_ok:
        lines.append(f"  WARNING: {report.integrity_note}")
    for change, title in (
        ("newly_denied", "Would now be DENIED"),
        ("newly_allowed", "Would now be ALLOWED"),
        ("flag_changed", "Flag status changed"),
    ):
        rows = [r for r in report.rows if r.change == change]
        lines.append(f"\n{title}: {len(rows)}")
        for r in rows:
            lines.append(f"  seq {r.seq:>3}  {r.tool:<11} {r.summary}")
            lines.append(f"           {r.old} -> {r.new}   rules: {', '.join(r.new_rules) or '-'}")
    lines.append(
        f"\nSummary: {c['newly_denied']} newly denied, {c['newly_allowed']} newly allowed, "
        f"{c['flag_changed']} flag changes, {c['unchanged']} unchanged"
    )
    return "\n".join(lines)
