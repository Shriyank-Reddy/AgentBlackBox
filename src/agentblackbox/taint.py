"""Data-origin labels and propagation.

Two labels exist: ``private_data`` (reads of configured private paths/tools) and
``untrusted_content`` (web tool results, reads of configured untrusted paths). Labels
attach to the *session* and to *values*: whenever a tool returns text, it is remembered
as a tainted value, and any later call whose arguments contain a meaningful fragment of
such a value inherits its label. That is how taint survives copying, summarising snippets
and re-encoding (the argument decoder exposes base64/hex/URL-encoded forms).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .normalize import NormalizedCall, normalize_path

PRIVATE = "private_data"
UNTRUSTED = "untrusted_content"
LABELS = (PRIVATE, UNTRUSTED)

PATH_ARGS = ("path", "file", "filename", "src", "source", "dir", "directory")
MAX_VALUE = 50_000
MIN_LITERAL = 6  # values shorter than min_fragment are matched whole, if at least this long


@dataclass(frozen=True)
class TaintConfig:
    """Which reads/tools create which label, from the policy's ``taint:`` section."""

    private_paths: tuple[str, ...] = ()
    untrusted_paths: tuple[str, ...] = ()
    private_tools: tuple[str, ...] = ()
    untrusted_tools: tuple[str, ...] = ()
    min_fragment: int = 16


@dataclass
class _Value:
    label: str
    grams: frozenset[int]  # hashes of every k-gram of the value
    literal: str | None  # whole value, for short values


def _squash(text: str) -> str:
    return re.sub(r"\s+", " ", text)[:MAX_VALUE]


def _meaningful(gram: str) -> bool:
    """Skip grams like '                ' or 'aaaaaaaaaaaaaaaa' that match anything."""
    return len(set(gram)) >= 5 and sum(c.isalnum() for c in gram) >= 8


@dataclass
class TaintTracker:
    config: TaintConfig
    sandbox_root: str = "/sandbox"
    session_labels: set[str] = field(default_factory=set)
    _values: list[_Value] = field(default_factory=list)

    # -- before the call: what do the arguments carry? ---------------------
    def call_labels(self, norm: NormalizedCall) -> set[str]:
        if not self._values:
            return set()
        found: set[str] = set()
        for _enc, text in norm.views():
            found |= self._labels_in(text)
        return found

    def _labels_in(self, text: str) -> set[str]:
        text = _squash(text)
        k = self.config.min_fragment
        found: set[str] = set()
        gram_hashes: set[int] | None = None
        for v in self._values:
            if v.label in found:
                continue
            if v.literal is not None:
                if v.literal in text:
                    found.add(v.label)
                continue
            if gram_hashes is None:
                gram_hashes = {hash(text[i : i + k]) for i in range(len(text) - k + 1)}
            if gram_hashes & v.grams:
                found.add(v.label)
        return found

    # -- after the call: label the result ----------------------------------
    def observe_result(self, tool: str, norm: NormalizedCall, result: object) -> set[str]:
        cfg = self.config
        text = result if isinstance(result, str) else repr(result)
        labels: set[str] = set()
        if tool in cfg.private_tools:
            labels.add(PRIVATE)
        if tool in cfg.untrusted_tools:
            labels.add(UNTRUSTED)
        for arg in PATH_ARGS:
            raw = norm.arg_text(arg)
            if raw is None:
                continue
            p = normalize_path(raw, self.sandbox_root)
            if p.under(list(cfg.private_paths)):
                labels.add(PRIVATE)
            if p.under(list(cfg.untrusted_paths)):
                labels.add(UNTRUSTED)
        labels |= self._labels_in(text) if self._values else set()  # copies stay tainted
        for label in sorted(labels):
            self._remember(label, text)
        self.session_labels |= labels
        return labels

    def _remember(self, label: str, text: str) -> None:
        text, k = _squash(text), self.config.min_fragment
        if len(text) >= k:
            grams = frozenset(
                hash(text[i : i + k])
                for i in range(len(text) - k + 1)
                if _meaningful(text[i : i + k])
            )
            if grams:
                self._values.append(_Value(label, grams, None))
        elif len(text) >= MIN_LITERAL:
            self._values.append(_Value(label, frozenset(), text))
