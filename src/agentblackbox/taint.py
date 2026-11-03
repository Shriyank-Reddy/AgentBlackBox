"""Data-origin labels and propagation (tracker added in M4)."""

from __future__ import annotations

from dataclasses import dataclass

PRIVATE = "private_data"
UNTRUSTED = "untrusted_content"
LABELS = (PRIVATE, UNTRUSTED)


@dataclass(frozen=True)
class TaintConfig:
    """Which reads/tools create which label, from the policy's ``taint:`` section."""

    private_paths: tuple[str, ...] = ()
    untrusted_paths: tuple[str, ...] = ()
    private_tools: tuple[str, ...] = ()
    untrusted_tools: tuple[str, ...] = ()
    min_fragment: int = 16
