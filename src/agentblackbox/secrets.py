"""Secret detection and redaction.

Everything here is pattern based and uses only documented *example* credentials in
tests. The same patterns serve two jobs: the policy rule ``any_arg_contains: secret``
and the recorder's redaction pass, so what the firewall treats as a secret is exactly
what the trace refuses to store.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from dataclasses import dataclass

CANARY_PREFIX = "ABB_CANARY_"

# (type, compiled regex). Order matters only for readability.
SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "private_key",
        re.compile(
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----(?:.*?-----END [A-Z ]*PRIVATE KEY-----)?", re.S
        ),
    ),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("slack_token", re.compile(r"\bxox[abprs]-[0-9A-Za-z-]{10,}")),
    ("stripe_key", re.compile(r"\b[sr]k_(?:live|test)_[0-9A-Za-z]{16,}")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}")),
    # "password" alone is not a secret; "password = <long value>" is.
    (
        "generic_secret",
        re.compile(
            r"(?i)\b(?:api[_-]?key|secret(?:[_-]?key)?|access[_-]?token|auth[_-]?token|passwd|password)"
            r"[\"']?\s*[:=]\s*[\"']?[A-Za-z0-9/+_\-.]{12,}"
        ),
    ),
    ("canary", re.compile(CANARY_PREFIX + r"[A-Za-z0-9_]{4,}")),
]

# Markers left behind by redaction. Replay re-reads redacted traces, so a marker
# must itself count as "a secret was here".
MARKER_RE = re.compile(r"\[REDACTED:([a-z_]+):([0-9a-f]{8})\]")

_B64_TOKEN = re.compile(r"[A-Za-z0-9+/_-]{16,}={0,2}")
_HEX_TOKEN = re.compile(r"\b(?:[0-9a-fA-F]{2}){8,}\b")


@dataclass(frozen=True)
class SecretHit:
    kind: str
    text: str


def marker(kind: str, value: str) -> str:
    digest = hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:8]
    return f"[REDACTED:{kind}:{digest}]"


def find_secrets(text: str) -> list[SecretHit]:
    """Secrets in ``text`` itself (no decoding). Redaction markers count as hits."""
    hits = [SecretHit(k, m.group(0)) for k, rx in SECRET_PATTERNS for m in rx.finditer(text)]
    hits += [SecretHit(m.group(1), m.group(0)) for m in MARKER_RE.finditer(text)]
    return hits


def decode_tokens(text: str):
    """Yield (token, encoding, decoded_text) for base64/hex tokens that decode to printable text."""
    for rx, decoders in ((_B64_TOKEN, (_b64, _b64url)), (_HEX_TOKEN, (_hex,))):
        for m in rx.finditer(text):
            for dec in decoders:
                out = dec(m.group(0))
                if out is not None:
                    yield m.group(0), dec.__name__.lstrip("_"), out
                    break


def _printable(raw: bytes) -> str | None:
    try:
        s = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if len(s) < 6 or sum(c.isprintable() or c in "\n\r\t" for c in s) / len(s) < 0.95:
        return None
    return s


def _b64(tok: str) -> str | None:
    try:
        return _printable(base64.b64decode(tok + "=" * (-len(tok) % 4), validate=True))
    except (binascii.Error, ValueError):
        return None


def _b64url(tok: str) -> str | None:
    try:
        return _printable(base64.urlsafe_b64decode(tok + "=" * (-len(tok) % 4)))
    except (binascii.Error, ValueError):
        return None


def _hex(tok: str) -> str | None:
    try:
        return _printable(bytes.fromhex(tok))
    except ValueError:
        return None


def redact_text(text: str, extra_literals: tuple[str, ...] = ()) -> str:
    """Replace secrets (and registered canary literals) with ``[REDACTED:type:hash8]``.

    The hash is of the original value, so two redactions of the same secret are
    visibly identical without revealing it.
    """
    # 1. Encoded blobs that hide a secret are replaced whole, before the plain pass.
    for tok, _enc, decoded in list(decode_tokens(text)):
        inner = [h for h in find_secrets(decoded) if not MARKER_RE.fullmatch(h.text)]
        inner += [SecretHit("canary", lit) for lit in extra_literals if lit and lit in decoded]
        if inner:
            text = text.replace(tok, marker("encoded_" + inner[0].kind, tok))
    # 2. Registered canary literals (exact, any position).
    for lit in extra_literals:
        if lit:
            text = text.replace(lit, marker("canary", lit))
    # 3. Pattern secrets in plain text.
    for kind, rx in SECRET_PATTERNS:
        text = rx.sub(lambda m, kind=kind: marker(kind, m.group(0)), text)
    return text
