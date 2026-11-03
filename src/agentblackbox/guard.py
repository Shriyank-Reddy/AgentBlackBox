"""The interceptor: every tool call passes through ``Guard.call``.

Pipeline: normalise -> (taint, canaries) -> evaluate policy -> decide -> record ->
run tool (only if allowed) -> record result summary.
"""

from __future__ import annotations

import functools
import inspect
from collections import Counter
from collections.abc import Callable
from typing import Any

from .canary import CanarySet
from .clock import FixedClock
from .normalize import NormalizedCall
from .policy import EvalContext, Policy, Verdict
from .recorder import Recorder, canonical_json
from .taint import TaintTracker


class PolicyViolation(Exception):
    """Raised in enforce mode when a call is denied."""

    def __init__(self, tool: str, verdict: Verdict) -> None:
        self.tool = tool
        self.verdict = verdict
        self.rule_ids = verdict.rule_ids
        why = "; ".join(verdict.reasons)
        super().__init__(f"{tool} denied by {', '.join(verdict.rule_ids)}: {why}")


class UnknownToolError(KeyError):
    """A call was allowed (monitor mode) but no implementation is registered."""


class Guard:
    def __init__(
        self,
        policy: Policy,
        recorder: Recorder | None = None,
        *,
        mode: str | None = None,
        clock: Callable[[], str] | None = None,
        session_id: str = "session",
        canaries: CanarySet | None = None,
    ) -> None:
        self.policy = policy
        self.mode = mode or policy.mode
        self.clock = clock or FixedClock()
        self.recorder = recorder or Recorder(None, session_id=session_id)
        self.tools: dict[str, Callable[..., Any]] = {}
        self.canaries = canaries
        self.taint = TaintTracker(policy.taint, policy.sandbox_root)
        self._call_counts: Counter[str] = Counter()
        self._total = 0
        self.canaries = canaries
        self.taint = TaintTracker(policy.taint, policy.sandbox_root)

    # -- registering tools -------------------------------------------------
    def wrap(self, tools: dict[str, Callable[..., Any]]) -> dict[str, Callable[..., Any]]:
        """Return guarded versions of every tool in ``tools``."""
        return {name: self._guarded(name, fn) for name, fn in tools.items()}

    def tool(self, fn: Callable[..., Any] | None = None, *, name: str | None = None):
        """Decorator form: ``@guard.tool`` or ``@guard.tool(name="x")``."""

        def deco(f: Callable[..., Any]) -> Callable[..., Any]:
            return self._guarded(name or f.__name__, f)

        return deco(fn) if fn else deco

    def _guarded(self, name: str, fn: Callable[..., Any]) -> Callable[..., Any]:
        self.tools[name] = fn
        sig = inspect.signature(fn)

        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            bound = sig.bind(*args, **kwargs)
            call_args: dict[str, Any] = {}
            for pname, value in bound.arguments.items():
                kind = sig.parameters[pname].kind
                if kind is inspect.Parameter.VAR_KEYWORD:
                    call_args.update(value)
                else:
                    call_args[pname] = value
            return self.call(name, call_args)

        return wrapper

    # -- the pipeline ------------------------------------------------------
    def call(self, name: str, args: dict[str, Any]) -> Any:
        rec = self.recorder
        norm = NormalizedCall(name, args, self.policy.sandbox_root)
        redacted = rec.redact(args)
        key = name + canonical_json(redacted)  # redacted so replay computes the same key
        self._call_counts[key] += 1
        self._total += 1
        # Canaries only matter on outbound tools; scanning elsewhere would just cost time.
        outbound = name in self.policy.outbound_tools
        hits = tuple(self.canaries.scan(norm)) if self.canaries and outbound else ()
        ctx = EvalContext(
            tool=name,
            norm=norm,
            session_labels=frozenset(self.taint.session_labels),
            call_labels=frozenset(self.taint.call_labels(norm)),
            same_call_count=self._call_counts[key],
            total_calls=self._total,
            canary_hits=hits,
        )
        verdict = self.policy.evaluate(ctx)
        blocked = verdict.decision == "deny" and self.mode == "enforce"
        event = rec.append(
            kind="call",
            tool=name,
            args=redacted,
            decision=verdict.decision,
            rule_ids=list(verdict.rule_ids),
            taint=self._taint_field(ctx),
            ts=self.clock(),
            pre_redacted=True,
            extra={
                "mode": self.mode,
                "blocked": blocked,
                "reasons": list(verdict.reasons),
                "severity": verdict.severity,
                **({"canary": list(hits)} if hits else {}),
            },
        )
        if blocked:
            raise PolicyViolation(name, verdict)
        fn = self.tools.get(name)
        if fn is None:
            raise UnknownToolError(name)
        try:
            result = fn(**args)
        except Exception as exc:
            rec.append(
                kind="result",
                tool=name,
                args={},
                decision=None,
                ts=self.clock(),
                result_summary={"error": f"{type(exc).__name__}: {exc}"},
                extra={"ref_seq": event["seq"]},
            )
            raise
        self.taint.observe_result(name, norm, result)
        rec.append(
            kind="result",
            tool=name,
            args={},
            decision=None,
            ts=self.clock(),
            result_summary=rec.summarize(result),
            extra={"ref_seq": event["seq"]},
        )
        return result

    @staticmethod
    def _taint_field(ctx: EvalContext) -> dict[str, list[str]]:
        return {"call": sorted(ctx.call_labels), "session": sorted(ctx.session_labels)}
