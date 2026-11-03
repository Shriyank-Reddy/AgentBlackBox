"""Injectable clocks so traces and hashes are identical run to run."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta


class FixedClock:
    """Starts at a fixed instant and advances a fixed step on every call."""

    def __init__(self, start: str = "2026-01-01T00:00:00", step_ms: int = 100) -> None:
        self._now = datetime.fromisoformat(start).replace(tzinfo=UTC)
        self._step = timedelta(milliseconds=step_ms)

    def __call__(self) -> str:
        value = self._now.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        self._now += self._step
        return value


class SystemClock:
    """Wall clock for real use (never used by tests or the benchmark)."""

    def __call__(self) -> str:
        return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
