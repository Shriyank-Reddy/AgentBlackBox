"""Hash-chained, tamper-evident JSONL trace writer and verifier.

Every event stores ``prev_hash`` (the previous event's hash) and its own ``hash``::

    hash = sha256(canonical_json(event_without_hash) + prev_hash)

Editing, deleting, inserting or reordering events breaks a link. Truncating the tail
leaves a *valid* chain, so we also keep a small ``<trace>.head`` file with the event
count and last hash, authenticated with an HMAC. Someone who can rewrite the trace but
does not hold the key cannot produce a matching head.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .canary import variants as canary_variants
from .secrets import marker, redact_text

GENESIS_HASH = "0" * 64
DEFAULT_HEAD_KEY = b"agentblackbox-demo-head-key"  # demo only; see docs/THREAT_MODEL.md
MAX_STR = 4000


def canonical_json(obj: Any) -> str:
    """Deterministic JSON: sorted keys, no whitespace, ASCII only."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def compute_hash(event_without_hash: dict[str, Any], prev_hash: str) -> str:
    return hashlib.sha256((canonical_json(event_without_hash) + prev_hash).encode()).hexdigest()


def head_path_for(trace_path: str | Path) -> Path:
    p = Path(trace_path)
    return p.with_name(p.name + ".head")


def _sign(key: bytes, count: int, last_hash: str) -> str:
    return hmac.new(key, f"{count}:{last_hash}".encode(), hashlib.sha256).hexdigest()


class Recorder:
    """Append-only trace writer. ``path=None`` keeps the chain in memory only."""

    def __init__(
        self,
        path: str | Path | None,
        session_id: str,
        canaries: list[str] | None = None,
        key: bytes = DEFAULT_HEAD_KEY,
        overwrite: bool = False,
        preview_chars: int = 60,
    ) -> None:
        self.session_id = session_id
        self.canaries = tuple(canaries or ())
        # Every encoding of a canary (reversed, base32, hex, ...) must stay out of the trace too.
        self._canary_needles = [
            (needle, marker("canary", tok))
            for tok in self.canaries
            for enc, needle in canary_variants(tok)
            if enc != "raw" and len(needle) >= 12
        ]
        self.key = key
        self.preview_chars = preview_chars
        self.events: list[dict[str, Any]] = []
        self._prev = GENESIS_HASH
        self._fh = None
        self.path = Path(path) if path else None
        if self.path:
            # "x" refuses to clobber an existing trace: evidence should not vanish silently.
            self._fh = open(self.path, "w" if overwrite else "x", encoding="utf-8")  # noqa: SIM115
            self._write_head()

    # -- redaction ---------------------------------------------------------
    def redact(self, value: Any) -> Any:
        """Recursively redact strings; cap very long strings."""
        if isinstance(value, str):
            s = redact_text(value, self.canaries)
            for needle, repl in self._canary_needles:
                s = s.replace(needle, repl)
            if len(s) <= MAX_STR:
                return s
            return s[:MAX_STR] + f"...[truncated {len(s) - MAX_STR} chars]"
        if isinstance(value, dict):
            return {str(k): self.redact(v) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return [self.redact(v) for v in value]
        return value

    def summarize(self, result: Any) -> dict[str, Any]:
        """Small description of a tool result: size, fingerprint, redacted preview."""
        text = result if isinstance(result, str) else repr(result)
        return {
            "len": len(text),
            "sha256": hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:16],
            "preview": self.redact(text[: self.preview_chars]),
        }

    # -- writing -----------------------------------------------------------
    def append(
        self,
        *,
        kind: str,
        tool: str,
        args: dict[str, Any],
        decision: str | None,
        rule_ids: list[str] | None = None,
        taint: dict[str, Any] | None = None,
        result_summary: Any = None,
        ts: str = "1970-01-01T00:00:00Z",
        extra: dict[str, Any] | None = None,
        pre_redacted: bool = False,
    ) -> dict[str, Any]:
        event: dict[str, Any] = {
            "seq": len(self.events),
            "ts": ts,
            "session_id": self.session_id,
            "kind": kind,
            "tool": tool,
            "args": args if pre_redacted else self.redact(args),
            "decision": decision,
            "rule_ids": list(rule_ids or []),
            "taint": taint or {"call": [], "session": []},
            "result_summary": result_summary,
            "prev_hash": self._prev,
        }
        if extra:
            event.update(self.redact(extra))
        event["hash"] = compute_hash(event, self._prev)
        self._prev = event["hash"]
        self.events.append(event)
        if self._fh:
            self._fh.write(canonical_json(event) + "\n")
            self._fh.flush()
            self._write_head()
        return event

    def head(self) -> dict[str, Any]:
        n = len(self.events)
        return {"count": n, "last_hash": self._prev, "sig": _sign(self.key, n, self._prev)}

    def _write_head(self) -> None:
        assert self.path is not None
        hp = head_path_for(self.path)
        tmp = hp.with_name(hp.name + ".tmp")
        tmp.write_text(json.dumps(self.head()), encoding="utf-8")
        os.replace(tmp, hp)  # atomic: a reader never sees half a head

    def close(self) -> None:
        if self._fh:
            self._fh.close()
            self._fh = None


# ---- verification --------------------------------------------------------


@dataclass
class VerifyError:
    seq: int
    reason: str


@dataclass
class VerifyResult:
    ok: bool
    count: int
    errors: list[VerifyError] = field(default_factory=list)

    @property
    def first_bad_seq(self) -> int | None:
        return self.errors[0].seq if self.errors else None


def read_events(path: str | Path) -> list[dict[str, Any]]:
    """Parse a trace without verifying it (the viewer and replay verify separately)."""
    out = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if line.strip():
            out.append(json.loads(line))
    return out


def verify_trace(path: str | Path, key: bytes = DEFAULT_HEAD_KEY) -> VerifyResult:
    """Check every link, then check the signed head. Reports the first broken ``seq``."""
    errors: list[VerifyError] = []
    prev = GENESIS_HASH
    count = 0
    lines = [ln for ln in Path(path).read_text(encoding="utf-8").splitlines() if ln.strip()]
    last_good_hash = GENESIS_HASH
    for i, line in enumerate(lines):
        try:
            ev = json.loads(line)
            if not isinstance(ev, dict):
                raise ValueError("not an object")
        except ValueError:
            errors.append(VerifyError(i, "line is not valid JSON"))
            break
        count += 1
        if ev.get("seq") != i:
            errors.append(
                VerifyError(
                    i,
                    f"expected seq {i}, found {ev.get('seq')} "
                    "(event deleted, inserted or reordered)",
                )
            )
            break
        if ev.get("prev_hash") != prev:
            errors.append(VerifyError(i, "prev_hash does not match previous event"))
            break
        body = {k: v for k, v in ev.items() if k != "hash"}
        if ev.get("hash") != compute_hash(body, prev):
            errors.append(VerifyError(i, "event content does not match its hash (edited)"))
            break
        prev = ev["hash"]
        last_good_hash = prev

    # Head check: catches truncation and wholesale re-hashing.
    hp = head_path_for(path)
    if not hp.exists():
        errors.append(VerifyError(count, "head file missing: truncation cannot be ruled out"))
    else:
        try:
            head = json.loads(hp.read_text(encoding="utf-8"))
            sig_ok = hmac.compare_digest(
                str(head.get("sig")), _sign(key, int(head["count"]), str(head["last_hash"]))
            )
        except (ValueError, KeyError, TypeError):
            head, sig_ok = {}, False
        if not sig_ok:
            errors.append(VerifyError(count, "head file signature invalid (forged or wrong key)"))
        elif not errors and (head["count"] != count or head["last_hash"] != last_good_hash):
            at = min(head["count"], count)
            errors.append(
                VerifyError(
                    at,
                    f"head says {head['count']} events ending {head['last_hash'][:12]}, "
                    f"trace has {count} (tail truncated or chain rewritten)",
                )
            )
    return VerifyResult(ok=not errors, count=count, errors=errors)
