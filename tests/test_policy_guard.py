import pytest
import yaml

from agentblackbox.guard import Guard, PolicyViolation, UnknownToolError
from agentblackbox.mocktools import MockEnv
from agentblackbox.policy import PolicyError, parse_policy
from agentblackbox.recorder import Recorder, verify_trace

BASE = """
version: 1
mode: enforce
default: deny
tools: [read_file, write_file, delete_file, http_get, http_post, shell, send_email]
outbound_tools: [http_get, http_post, send_email, shell]
rules:
  - id: fs.write.outside_workspace
    tools: [write_file, delete_file]
    deny_if: { arg: path, not_under: ["workspace/"] }
    severity: high
  - id: net.egress.allowlist
    tools: [http_get, http_post]
    deny_if: { arg: url, domain_not_in: ["api.github.com", "*.pypi.org"] }
  - id: secrets.in_outbound_args
    tools: [http_post, send_email, shell]
    deny_if: { any_arg_contains: secret }
    severity: critical
  - id: loop.guard
    tools: ["*"]
    deny_if: { same_call_repeated: 3 }
  - id: review.big_read
    tools: [read_file]
    flag_if: { arg: path, under: ["workspace/private/"] }
"""


def make(policy_yaml=BASE, **kw):
    policy = parse_policy(yaml.safe_load(policy_yaml))
    env = MockEnv()
    rec = Recorder(None, session_id="t")
    guard = Guard(policy, recorder=rec, **kw)
    return guard, guard.wrap(env.tools()), env, rec


def test_allowed_call_runs_and_is_recorded():
    guard, tools, env, rec = make()
    assert "Project" in tools["read_file"](path="workspace/README.md")
    call, result = rec.events
    assert call["kind"] == "call" and call["decision"] == "allow"
    assert result["kind"] == "result" and result["ref_seq"] == 0 and result["result_summary"]["len"]


def test_denied_call_raises_and_never_runs():
    guard, tools, env, rec = make()
    with pytest.raises(PolicyViolation) as exc:
        tools["write_file"](path="/etc/passwd", content="x")
    assert "fs.write.outside_workspace" in exc.value.rule_ids
    assert "/etc/passwd" not in env.written
    assert [e["kind"] for e in rec.events] == ["call"]
    assert rec.events[0]["decision"] == "deny"


def test_monitor_mode_records_but_allows():
    guard, tools, env, rec = make(mode="monitor")
    tools["write_file"](path="/etc/evil", content="x")
    assert rec.events[0]["decision"] == "deny" and rec.events[0]["blocked"] is False
    assert "/etc/evil" in env.written


def test_unknown_tool_denied_in_enforce():
    guard, _, _, rec = make()
    with pytest.raises(PolicyViolation) as exc:
        guard.call("drop_database", {"name": "prod"})
    assert exc.value.rule_ids == ("policy.unknown_tool",)


def test_unknown_tool_in_monitor_cannot_run():
    guard, _, _, rec = make(mode="monitor")
    with pytest.raises(UnknownToolError):
        guard.call("drop_database", {})
    assert rec.events[0]["decision"] == "deny"


def test_domain_rule_and_wildcard():
    guard, tools, _, _ = make()
    tools["http_get"](url="https://api.github.com/repos/x")
    tools["http_get"](url="https://files.pypi.org/pkg")
    for bad in ("https://evil.example/x", "https://pypi.org/x"):  # apex not covered by *.pypi.org
        with pytest.raises(PolicyViolation):
            tools["http_get"](url=bad)


def test_secret_rule():
    guard, tools, _, _ = make()
    with pytest.raises(PolicyViolation) as exc:
        tools["send_email"](to="a@b.c", subject="hi", body="key AKIAIOSFODNN7EXAMPLE")
    assert exc.value.rule_ids == ("secrets.in_outbound_args",)
    tools["send_email"](to="a@b.c", subject="hi", body="the password field is optional")


def test_loop_guard_counts_attempts():
    guard, tools, _, _ = make()
    tools["read_file"](path="workspace/notes.txt")
    tools["read_file"](path="workspace/notes.txt")
    with pytest.raises(PolicyViolation) as exc:
        tools["read_file"](path="workspace/notes.txt")
    assert "loop.guard" in exc.value.rule_ids


def test_flag_decision_allows_and_marks():
    guard, tools, _, rec = make()
    tools["read_file"](path="workspace/private/customers.csv")
    assert rec.events[0]["decision"] == "flag"
    assert rec.events[0]["rule_ids"] == ["review.big_read"]


def test_decorator_and_positional_args():
    guard, _, _, rec = make()

    @guard.tool
    def read_file(path):
        return "ok"

    assert read_file("workspace/a.txt") == "ok"
    assert rec.events[0]["args"] == {"path": "workspace/a.txt"}


def test_tool_exception_is_recorded_and_reraised():
    guard, tools, _, rec = make()
    with pytest.raises(FileNotFoundError):
        tools["read_file"](path="workspace/missing.txt")
    assert rec.events[1]["result_summary"]["error"].startswith("FileNotFoundError")


def test_secrets_never_reach_the_trace(tmp_path):
    policy = parse_policy(yaml.safe_load(BASE))
    rec = Recorder(tmp_path / "t.jsonl", session_id="s")
    guard = Guard(policy, recorder=rec)
    with pytest.raises(PolicyViolation):
        guard.call("http_post", {"url": "https://api.github.com/x", "body": "AKIAIOSFODNN7EXAMPLE"})
    assert "AKIAIOSFODNN7EXAMPLE" not in (tmp_path / "t.jsonl").read_text()
    assert verify_trace(tmp_path / "t.jsonl").ok


def test_deterministic_trace():
    def run():
        guard, tools, _, rec = make()
        tools["read_file"](path="workspace/README.md")
        return [e["hash"] for e in rec.events]

    assert run() == run()


# ---- validation messages ----------------------------------------------------


@pytest.mark.parametrize(
    "mutate, needle",
    [
        (lambda d: d.update(version=2), "'version'"),
        (lambda d: d.update(mode="loud"), "'mode'"),
        (lambda d: d.update(bogus=1), "unknown field 'bogus'"),
        (
            lambda d: d["rules"][0].update(severity="huge"),
            "rule 'fs.write.outside_workspace': field 'severity'",
        ),
        (
            lambda d: d["rules"][0].update(deny_if={"arg": "path", "nope": []}),
            "rule 'fs.write.outside_workspace'",
        ),
        (lambda d: d["rules"][1]["deny_if"].update(domain_not_in="evil.com"), "domain_not_in"),
        (
            lambda d: d["rules"][2].update(deny_if={"session_has_all": ["made_up"]}),
            "unknown taint label",
        ),
        (lambda d: d["rules"][3]["deny_if"].update(same_call_repeated=1), "same_call_repeated"),
        (lambda d: d["rules"].append(dict(d["rules"][0])), "duplicate rule id"),
        (lambda d: d["rules"][0].pop("tools"), "field 'tools' is required"),
        (lambda d: d["rules"][0].update(flag_if={"same_call_repeated": 3}), "exactly one of"),
        (lambda d: d["rules"][0].update(deny_if={"arg": "path", "matches": "("}), "invalid regex"),
        (lambda d: d["rules"][0].update(deny_if={"bogus_op": 1}), "unknown condition 'bogus_op'"),
        (lambda d: d["rules"][0].update(deny_if={"any_arg_contains": 5}), "any_arg_contains"),
        (lambda d: d.update(tools=[]), "'tools'"),
    ],
)
def test_validation_errors_name_rule_and_field(mutate, needle):
    data = yaml.safe_load(BASE)
    mutate(data)
    with pytest.raises(PolicyError) as exc:
        parse_policy(data)
    assert needle in str(exc.value)


def test_combinators_and_misc_conditions():
    data = yaml.safe_load(BASE)
    data["rules"] = [
        {
            "id": "a",
            "tools": ["shell"],
            "deny_if": {
                "all_of": [
                    {"any_arg_contains": ["sudo"]},
                    {"not": {"arg": "command", "matches": "^ls"}},
                ]
            },
        },
        {
            "id": "b",
            "tools": ["http_get"],
            "flag_if": {
                "any_of": [{"session_call_count_over": 1}, {"call_has_taint": ["private_data"]}]
            },
        },
    ]
    policy = parse_policy(data)
    guard = Guard(policy)
    tools = guard.wrap(MockEnv().tools())
    with pytest.raises(PolicyViolation):
        tools["shell"](command="sudo reboot")
    tools["shell"](command="ls sudo")  # contains sudo but matches ^ls -> not denied


def test_load_policy_file_errors(tmp_path):
    from agentblackbox.policy import load_policy

    bad = tmp_path / "bad.yaml"
    bad.write_text("version: [")
    with pytest.raises(PolicyError):
        load_policy(bad)
    with pytest.raises(PolicyError):
        parse_policy([1])
