"""Argument normalisation: turn attacker-controlled strings into canonical facts.

Rules never look at raw strings. They ask a ``NormalizedCall`` for the canonical path,
URL host, decoded views or shell findings, so every evasion trick is handled in one place.
"""

from __future__ import annotations

import posixpath
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import unquote, urlsplit

HOME_DIR = "/home/agent"  # virtual home directory for "~"


# ---- paths ---------------------------------------------------------------
@dataclass(frozen=True)
class NormPath:
    raw: str
    abs: str  # canonical absolute path inside the *virtual* filesystem
    root: str
    flags: frozenset[str] = frozenset()

    @property
    def inside_root(self) -> bool:
        return self.abs == self.root or self.abs.startswith(self.root.rstrip("/") + "/")

    def under(self, prefixes: list[str]) -> bool:
        """True if the path is at or below any prefix (relative prefixes are sandbox-relative)."""
        for pre in prefixes:
            base = pre if pre.startswith("/") else posixpath.join(self.root, pre)
            base = posixpath.normpath(base)
            if self.abs == base or self.abs.startswith(base.rstrip("/") + "/"):
                return True
        return False


def normalize_path(raw: str, root: str = "/sandbox") -> NormPath:
    flags: set[str] = set()
    p = raw.replace("\x00", "").strip()
    for _ in range(3):  # decode %2e%2e%2f style separators (repeatedly: %252e)
        dec = unquote(p)
        if dec == p:
            break
        flags.add("encoded")
        p = dec
    if "\\" in p:
        flags.add("backslash")
        p = p.replace("\\", "/")
    if p == "~" or p.startswith("~/"):
        flags.add("home")
        p = HOME_DIR + p[1:]
    if p.startswith("/"):
        flags.add("absolute")
    if "//" in p:
        flags.add("doubled_slash")
    if ".." in p.split("/"):
        flags.add("traversal")
    full = p if p.startswith("/") else posixpath.join(root, p)
    return NormPath(raw, posixpath.normpath(full) if full else root, root, frozenset(flags))


# ---- URLs (minimal; extended in M3) --------------------------------------
@dataclass(frozen=True)
class NormURL:
    raw: str
    scheme: str
    host: str
    port: int | None
    flags: frozenset[str] = frozenset()

    def host_in(self, patterns: list[str]) -> bool:
        return host_matches(self.host, patterns)


def host_matches(host: str, patterns: list[str]) -> bool:
    for pat in patterns:
        pat = pat.lower().rstrip(".")
        if pat.startswith("*."):
            if host.endswith(pat[1:]):
                return True
        elif host == pat:
            return True
    return False


def normalize_url(raw: str) -> NormURL:
    parts = urlsplit(raw.strip())
    return NormURL(
        raw,
        parts.scheme.lower(),
        (parts.hostname or "").lower().rstrip("."),
        parts.port,
        frozenset(),
    )


# ---- the per-call facade --------------------------------------------------
@dataclass
class NormalizedCall:
    tool: str
    args: dict[str, Any]
    sandbox_root: str = "/sandbox"
    _cache: dict[Any, Any] = field(default_factory=dict, repr=False)

    def _memo(self, key: Any, fn):
        if key not in self._cache:
            self._cache[key] = fn()
        return self._cache[key]

    def arg_text(self, name: str) -> str | None:
        v = self.args.get(name)
        return v if isinstance(v, str) else None

    def path(self, name: str) -> NormPath | None:
        t = self.arg_text(name)
        return (
            None
            if t is None
            else self._memo(("p", name), lambda: normalize_path(t, self.sandbox_root))
        )

    def url(self, name: str) -> NormURL | None:
        t = self.arg_text(name)
        return None if t is None else self._memo(("u", name), lambda: normalize_url(t))

    def views(self) -> list[tuple[str, str]]:
        """Every string in the arguments, as (encoding, text) pairs."""
        return self._memo("views", lambda: [("raw", t) for t in _strings(self.args)])

    def shell_findings(self, name: str) -> list[str]:
        return []


def _strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for v in value.values() for s in _strings(v)]
    if isinstance(value, (list, tuple)):
        return [s for v in value for s in _strings(v)]
    return [] if value is None else [str(value)]


URL_RE = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://[^\s'\"<>]+")
