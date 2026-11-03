"""Scripted scenarios: a metadata header plus a fixed list of tool calls.

A scenario "agent" is just a list of calls. Nothing here is an LLM. That keeps every run
deterministic and free, and it means the benchmark measures the *firewall*, not a model.
"""

from __future__ import annotations

import importlib.util
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .canary import CanarySet
from .clock import FixedClock
from .guard import Guard, PolicyViolation
from .mocktools import MockEnv
from .policy import Policy
from .recorder import Recorder

LLM01 = "LLM01:2025 Prompt Injection"
LLM02 = "LLM02:2025 Sensitive Information Disclosure"
LLM05 = "LLM05:2025 Improper Output Handling"
LLM06 = "LLM06:2025 Excessive Agency"
LLM10 = "LLM10:2025 Unbounded Consumption"
OWASP_IDS = {LLM01, LLM02, LLM05, LLM06, LLM10}

# dyn() argument builders receive (results of earlier calls, the canary set).
ArgBuilder = Callable[[list[Any], CanarySet], dict[str, Any]]


@dataclass(frozen=True)
class Call:
    tool: str
    args: dict[str, Any] | None = None
    build: ArgBuilder | None = None


def call(tool: str, **args: Any) -> Call:
    """A call with fixed arguments."""
    return Call(tool, args=args)


def dyn(tool: str, build: ArgBuilder) -> Call:
    """A call whose arguments depend on earlier results, as a real agent's would."""
    return Call(tool, build=build)


@dataclass(frozen=True)
class Scenario:
    id: str
    category: str
    title: str
    expected: str  # "block" (attack) or "allow" (benign)
    calls: tuple[Call, ...]
    owasp: tuple[str, ...] = ()
    expected_rules: tuple[str, ...] = ()  # any of these firing counts as "right reason"
    files: dict[str, str] = field(default_factory=dict)
    web: dict[str, str] = field(default_factory=dict)
    env_vars: dict[str, str] = field(default_factory=dict)
    note: str = ""  # e.g. why a scenario is a known limitation


def attack(
    id: str,
    category: str,
    title: str,
    owasp: tuple[str, ...],
    calls: list[Call],
    rules: tuple[str, ...] = (),
    **kw: Any,
) -> Scenario:
    return Scenario(id, category, title, "block", tuple(calls), owasp, rules, **kw)


def benign(id: str, category: str, title: str, calls: list[Call], **kw: Any) -> Scenario:
    return Scenario(id, category, title, "allow", tuple(calls), (), (), **kw)


def load_scenarios(directory: str | Path) -> list[Scenario]:
    """Import every ``*.py`` under ``directory`` (not starting with ``_``) and collect SCENARIOS."""
    found: list[Scenario] = []
    for path in sorted(Path(directory).rglob("*.py")):
        if path.name.startswith("_"):
            continue
        spec = importlib.util.spec_from_file_location(f"abb_scn_{path.stem}", path)
        assert spec and spec.loader
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        found.extend(getattr(mod, "SCENARIOS", []))
    ids = [s.id for s in found]
    dupes = {i for i in ids if ids.count(i) > 1}
    if dupes:
        raise ValueError(f"duplicate scenario ids: {sorted(dupes)}")
    for s in found:
        if s.expected not in ("block", "allow"):
            raise ValueError(f"{s.id}: expected must be 'block' or 'allow'")
        if unknown := set(s.owasp) - OWASP_IDS:
            raise ValueError(f"{s.id}: unknown OWASP id {unknown}")
    return found


@dataclass
class ScenarioResult:
    id: str
    category: str
    expected: str
    blocked: bool  # a call was denied (and, in enforce mode, stopped)
    blocked_at: int | None
    rule_ids: list[str]
    flagged: bool
    decisions: list[str]
    right_reason: bool | None  # None when the scenario declares no expected rules
    trace: list[dict[str, Any]] = field(repr=False, default_factory=list)

    @property
    def correct(self) -> bool:
        return self.blocked if self.expected == "block" else not self.blocked


def run_scenario(scenario: Scenario, policy: Policy, seed: int = 1337) -> ScenarioResult:
    """Run one scripted agent against a fresh guard and mock environment."""
    canaries = CanarySet(seed)
    env = MockEnv(policy.sandbox_root, scenario.files, scenario.web, scenario.env_vars)
    canaries.plant(env)
    rec = Recorder(None, session_id=scenario.id, canaries=canaries.literals())
    guard = Guard(
        policy, recorder=rec, clock=FixedClock(), canaries=canaries, session_id=scenario.id
    )
    guard.tools.update(env.tools())  # register implementations without a wrapper layer
    results: list[Any] = []
    blocked_at: int | None = None
    rules: list[str] = []
    for i, c in enumerate(scenario.calls):
        args = c.build(results, canaries) if c.build else dict(c.args or {})
        try:
            results.append(guard.call(c.tool, args))
        except PolicyViolation as exc:
            blocked_at, rules = i, list(exc.rule_ids)
            break  # a blocked scripted agent stops, like an agent that gives up
        except Exception:  # tool errors (e.g. missing file) do not stop the script
            results.append(None)
    calls = [e for e in rec.events if e["kind"] == "call"]
    decisions = [e["decision"] for e in calls]
    right = None
    if scenario.expected_rules and blocked_at is not None:
        right = bool(set(rules) & set(scenario.expected_rules))
    return ScenarioResult(
        scenario.id,
        scenario.category,
        scenario.expected,
        blocked_at is not None,
        blocked_at,
        rules,
        "flag" in decisions,
        decisions,
        right,
        rec.events,
    )
