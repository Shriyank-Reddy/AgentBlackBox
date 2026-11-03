"""YAML policy loading, validation and evaluation. Schema: docs/POLICY.md."""

from __future__ import annotations

import fnmatch
import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from .normalize import URL_RE, NormalizedCall, host_matches, normalize_url
from .secrets import find_secrets
from .taint import LABELS, TaintConfig

SEVERITIES = ("low", "medium", "high", "critical")
RULE_UNKNOWN_TOOL = "policy.unknown_tool"
RULE_CANARY = "canary.exfil"


class PolicyError(ValueError):
    """Raised for an invalid policy; the message names the rule and field."""


@dataclass
class EvalContext:
    """Everything a rule may look at for one call."""

    tool: str
    norm: NormalizedCall
    session_labels: frozenset[str] = frozenset()
    call_labels: frozenset[str] = frozenset()
    same_call_count: int = 1
    total_calls: int = 1
    canary_hits: tuple[str, ...] = ()

    @property
    def all_labels(self) -> frozenset[str]:
        return self.session_labels | self.call_labels


@dataclass(frozen=True)
class Verdict:
    decision: str  # allow | deny | flag
    rule_ids: tuple[str, ...] = ()
    reasons: tuple[str, ...] = ()
    severity: str | None = None


Check = Callable[[EvalContext], "str | None"]  # returns a reason if the condition holds


@dataclass(frozen=True)
class Rule:
    id: str
    tools: tuple[str, ...]
    action: str  # deny | flag
    check: Check
    severity: str = "medium"
    description: str = ""

    def applies_to(self, tool: str) -> bool:
        return any(fnmatch.fnmatchcase(tool, pat) for pat in self.tools)


@dataclass(frozen=True)
class Policy:
    version: int
    mode: str
    default: str
    tools: tuple[str, ...]
    sandbox_root: str
    outbound_tools: tuple[str, ...]
    taint: TaintConfig
    rules: tuple[Rule, ...]

    def evaluate(self, ctx: EvalContext) -> Verdict:
        """Decide one call. Order: canary (cannot be overridden) > unknown tool > rules."""
        deny: list[tuple[str, str, str]] = []
        flag: list[tuple[str, str, str]] = []
        if ctx.canary_hits and ctx.tool in self.outbound_tools:
            deny.append((RULE_CANARY, "critical", f"canary {ctx.canary_hits[0]} in outbound call"))
        if self.default == "deny" and ctx.tool not in self.tools:
            deny.append((RULE_UNKNOWN_TOOL, "high", f"tool '{ctx.tool}' is not allow-listed"))
        for rule in self.rules:
            if not rule.applies_to(ctx.tool):
                continue
            reason = rule.check(ctx)
            if reason:
                (deny if rule.action == "deny" else flag).append((rule.id, rule.severity, reason))
        hits = deny or flag
        decision = "deny" if deny else "flag" if flag else "allow"
        order = {s: i for i, s in enumerate(SEVERITIES)}
        sev = max((h[1] for h in hits), key=lambda s: order[s]) if hits else None
        return Verdict(
            decision, tuple(h[0] for h in deny + flag), tuple(h[2] for h in deny + flag), sev
        )


# ---- loading and validation ----------------------------------------------


def load_policy(path: str | Path) -> Policy:
    try:
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise PolicyError(f"{path}: invalid YAML: {exc}") from exc
    return parse_policy(data)


def parse_policy(data: Any) -> Policy:
    if not isinstance(data, dict):
        raise PolicyError("policy must be a YAML mapping")
    _only_keys(
        data,
        {"version", "mode", "default", "tools", "sandbox_root", "outbound_tools", "taint", "rules"},
        "policy",
    )
    if data.get("version") != 1:
        raise PolicyError("policy: field 'version' must be 1")
    mode = data.get("mode", "enforce")
    if mode not in ("enforce", "monitor"):
        raise PolicyError("policy: field 'mode' must be 'enforce' or 'monitor'")
    default = data.get("default", "deny")
    if default not in ("deny", "allow"):
        raise PolicyError("policy: field 'default' must be 'deny' or 'allow'")
    tools = _str_list(data.get("tools", []), "policy: field 'tools'")
    if default == "deny" and not tools:
        raise PolicyError("policy: field 'tools' must list the allowed tools when default is deny")
    root = data.get("sandbox_root", "/sandbox")
    if not isinstance(root, str) or not root.startswith("/"):
        raise PolicyError("policy: field 'sandbox_root' must be an absolute path string")
    outbound = _str_list(data.get("outbound_tools", []), "policy: field 'outbound_tools'")
    taint = _parse_taint(data.get("taint") or {})
    raw_rules = data.get("rules", [])
    if not isinstance(raw_rules, list):
        raise PolicyError("policy: field 'rules' must be a list")
    rules, seen = [], set()
    for i, raw in enumerate(raw_rules):
        rule = _parse_rule(raw, i)
        if rule.id in seen:
            raise PolicyError(f"rule '{rule.id}': duplicate rule id")
        seen.add(rule.id)
        rules.append(rule)
    return Policy(
        1,
        mode,
        default,
        tuple(tools),
        root.rstrip("/") or "/",
        tuple(outbound),
        taint,
        tuple(rules),
    )


def _only_keys(d: dict, allowed: set[str], where: str) -> None:
    for k in d:
        if k not in allowed:
            raise PolicyError(
                f"{where}: unknown field '{k}' (allowed: {', '.join(sorted(allowed))})"
            )


def _str_list(v: Any, where: str) -> list[str]:
    if not isinstance(v, list) or not all(isinstance(x, str) and x for x in v):
        raise PolicyError(f"{where} must be a list of non-empty strings")
    return v


def _parse_taint(d: Any) -> TaintConfig:
    if not isinstance(d, dict):
        raise PolicyError("policy: field 'taint' must be a mapping")
    _only_keys(
        d,
        {"private_paths", "untrusted_paths", "private_tools", "untrusted_tools", "min_fragment"},
        "taint",
    )
    frag = d.get("min_fragment", 16)
    if not isinstance(frag, int) or isinstance(frag, bool) or frag < 4:
        raise PolicyError("taint: field 'min_fragment' must be an integer >= 4")
    lists = {
        k: tuple(_str_list(d.get(k, []), f"taint: field '{k}'"))
        for k in ("private_paths", "untrusted_paths", "private_tools", "untrusted_tools")
    }
    return TaintConfig(min_fragment=frag, **lists)


def _parse_rule(raw: Any, index: int) -> Rule:
    if not isinstance(raw, dict):
        raise PolicyError(f"rules[{index}]: must be a mapping")
    rid = raw.get("id")
    if not isinstance(rid, str) or not rid:
        raise PolicyError(f"rules[{index}]: field 'id' is required")
    where = f"rule '{rid}'"
    _only_keys(raw, {"id", "tools", "deny_if", "flag_if", "severity", "description"}, where)
    tools = _str_list(raw.get("tools", []), f"{where}: field 'tools'")
    if not tools:
        raise PolicyError(f"{where}: field 'tools' is required")
    has_deny, has_flag = "deny_if" in raw, "flag_if" in raw
    if has_deny == has_flag:
        raise PolicyError(f"{where}: exactly one of 'deny_if' or 'flag_if' is required")
    action = "deny" if has_deny else "flag"
    sev = raw.get("severity", "medium")
    if sev not in SEVERITIES:
        raise PolicyError(f"{where}: field 'severity' must be one of {', '.join(SEVERITIES)}")
    cond_key = "deny_if" if has_deny else "flag_if"
    check = compile_condition(raw[cond_key], f"{where}: field '{cond_key}'")
    return Rule(rid, tuple(tools), action, check, sev, str(raw.get("description", "")))


ARG_OPS = {
    "not_under",
    "under",
    "domain_not_in",
    "domain_in",
    "urls_not_in",
    "matches",
    "shell_dangerous",
}
GLOBAL_OPS = {
    "any_arg_contains",
    "session_has_all",
    "session_has_any",
    "call_has_taint",
    "same_call_repeated",
    "session_call_count_over",
}
COMBINATORS = {"all_of", "any_of", "not"}


def compile_condition(spec: Any, where: str) -> Check:
    if not isinstance(spec, dict) or not spec:
        raise PolicyError(f"{where} must be a non-empty mapping")
    if "arg" in spec:
        return _compile_arg_condition(spec, where)
    if len(spec) != 1:
        raise PolicyError(f"{where}: expected exactly one condition, got {sorted(spec)}")
    ((key, val),) = spec.items()
    sub = f"{where}.{key}"
    if key in ("all_of", "any_of"):
        if not isinstance(val, list) or not val:
            raise PolicyError(f"{sub} must be a non-empty list of conditions")
        checks = [compile_condition(v, f"{sub}[{i}]") for i, v in enumerate(val)]
        if key == "all_of":

            def all_of(ctx: EvalContext) -> str | None:
                reasons = [c(ctx) for c in checks]
                return "; ".join(reasons) if all(reasons) else None  # type: ignore[arg-type]

            return all_of

        def any_of(ctx: EvalContext) -> str | None:
            return next((r for c in checks if (r := c(ctx))), None)

        return any_of
    if key == "not":
        inner = compile_condition(val, sub)
        return lambda ctx: None if inner(ctx) else "negated condition holds"
    if key == "any_arg_contains":
        return _compile_contains(val, sub)
    if key in ("session_has_all", "session_has_any", "call_has_taint"):
        labels = _labels(val, sub)
        if key == "session_has_all":
            return lambda ctx: (
                f"session has {','.join(labels)}" if set(labels) <= ctx.all_labels else None
            )
        if key == "session_has_any":
            return lambda ctx: (
                f"session has one of {','.join(labels)}" if set(labels) & ctx.all_labels else None
            )
        return lambda ctx: (
            f"call arguments derive from {','.join(sorted(set(labels) & ctx.call_labels))}"
            if set(labels) & ctx.call_labels
            else None
        )
    if key in ("same_call_repeated", "session_call_count_over"):
        if (
            not isinstance(val, int)
            or isinstance(val, bool)
            or val < 2 - (key != "same_call_repeated")
        ):
            raise PolicyError(
                f"{sub} must be an integer >= {2 if key == 'same_call_repeated' else 1}"
            )
        if key == "same_call_repeated":
            return lambda ctx: (
                f"identical call made {ctx.same_call_count} times"
                if ctx.same_call_count >= val
                else None
            )
        return lambda ctx: (
            f"{ctx.total_calls} calls this session (limit {val})" if ctx.total_calls > val else None
        )
    raise PolicyError(f"{where}: unknown condition '{key}'")


def _labels(val: Any, where: str) -> list[str]:
    labs = _str_list(val, where)
    for lab in labs:
        if lab not in LABELS:
            raise PolicyError(f"{where}: unknown taint label '{lab}' (known: {', '.join(LABELS)})")
    return labs


def _compile_contains(val: Any, where: str) -> Check:
    if val == "secret":

        def has_secret(ctx: EvalContext) -> str | None:
            for enc, text in ctx.norm.views():
                hits = find_secrets(text)
                if hits:
                    via = "" if enc == "raw" else f" (found via {enc} decoding)"
                    return f"secret of type {hits[0].kind} in arguments{via}"
            return None

        return has_secret
    words = _str_list(val, where) if isinstance(val, list) else None
    if words is None:
        raise PolicyError(f"{where} must be 'secret' or a list of strings")
    lowered = [w.lower() for w in words]

    def has_word(ctx: EvalContext) -> str | None:
        for _, text in ctx.norm.views():
            t = text.lower()
            for w in lowered:
                if w in t:
                    return f"argument contains '{w}'"
        return None

    return has_word


def _compile_arg_condition(spec: dict, where: str) -> Check:
    arg = spec["arg"]
    if not isinstance(arg, str) or not arg:
        raise PolicyError(f"{where}.arg must be a non-empty string")
    ops = [k for k in spec if k != "arg"]
    if len(ops) != 1 or ops[0] not in ARG_OPS:
        raise PolicyError(f"{where}: with 'arg', give exactly one of {', '.join(sorted(ARG_OPS))}")
    op, val = ops[0], spec[ops[0]]
    sub = f"{where}.{op}"
    if op == "shell_dangerous":
        if val is not True:
            raise PolicyError(f"{sub} must be true")

        def dangerous(ctx: EvalContext) -> str | None:
            found = ctx.norm.shell_findings(arg)
            return f"dangerous shell pattern(s) in '{arg}': {', '.join(found)}" if found else None

        return dangerous
    if op == "matches":
        if not isinstance(val, str):
            raise PolicyError(f"{sub} must be a regex string")
        try:
            rx = re.compile(val)
        except re.error as exc:
            raise PolicyError(f"{sub}: invalid regex: {exc}") from exc

        def matches(ctx: EvalContext) -> str | None:
            t = ctx.norm.arg_text(arg)
            return f"'{arg}' matches /{val}/" if t is not None and rx.search(t) else None

        return matches
    items = _str_list(val, sub)
    if op in ("not_under", "under"):

        def path_check(ctx: EvalContext) -> str | None:
            p = ctx.norm.path(arg)
            if p is None:
                return None
            inside = p.under(items)
            if op == "not_under" and not inside:
                return f"path '{arg}' resolves to {p.abs}, outside {items}"
            if op == "under" and inside:
                return f"path '{arg}' resolves to {p.abs}, inside {items}"
            return None

        return path_check
    if op == "urls_not_in":

        def urls_check(ctx: EvalContext) -> str | None:
            t = ctx.norm.arg_text(arg)
            for m in URL_RE.finditer(t or ""):
                u = normalize_url(m.group(0))
                if not host_matches(u.host, items) or u.flags & BAD_URL_FLAGS:
                    return f"URL host '{u.host}' in '{arg}' not in allowlist"
            return None

        return urls_check

    def domain_check(ctx: EvalContext) -> str | None:
        u = ctx.norm.url(arg)
        if u is None:
            return None
        listed = host_matches(u.host, items) and not (u.flags & BAD_URL_FLAGS)
        if op == "domain_not_in" and not listed:
            return f"host '{u.host}' (from '{arg}') not in allowlist"
        if op == "domain_in" and listed:
            return f"host '{u.host}' (from '{arg}') is listed"
        return None

    return domain_check


# URL oddities that make an allowlist match untrustworthy (set by normalize_url in M3).
BAD_URL_FLAGS = frozenset({"userinfo", "bad_scheme", "bad_host", "ip_literal", "backslash"})
