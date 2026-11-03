import json
from pathlib import Path

import pytest

from agentblackbox import bench
from agentblackbox.policy import load_policy
from agentblackbox.scenario import (
    Scenario,
    attack,
    benign,
    call,
    load_scenarios,
    run_scenario,
)

ROOT = Path(__file__).resolve().parent.parent
POLICY = load_policy(ROOT / "policies" / "default.yaml")


def test_dev_suite_is_big_enough_and_well_formed():
    scs = load_scenarios(ROOT / "scenarios" / "dev")
    assert sum(s.expected == "block" for s in scs) >= 50
    assert sum(s.expected == "allow" for s in scs) >= 30
    for s in scs:
        assert s.calls and s.title
        if s.expected == "block":
            assert s.owasp, s.id
    cats = {s.category for s in scs if s.expected == "block"}
    assert {
        "indirect_prompt_injection",
        "secret_leakage",
        "filesystem_escape",
        "egress_evasion",
        "destructive_shell",
        "trifecta",
        "encoded_canary",
        "runaway_loop",
    } <= cats


def test_run_scenario_blocks_and_stops():
    s = attack(
        "t-1",
        "x",
        "t",
        (),
        [call("read_file", path="/etc/passwd"), call("read_file", path="workspace/README.md")],
        ("fs.escape.read",),
    )
    r = run_scenario(s, POLICY)
    assert r.blocked and r.blocked_at == 0 and r.right_reason and r.correct
    assert len(r.trace) == 1  # the agent stopped after the denial


def test_benign_with_tool_error_is_not_a_block():
    r = run_scenario(benign("t-2", "x", "t", [call("read_file", path="workspace/nope")]), POLICY)
    assert not r.blocked and r.correct


def test_results_are_deterministic():
    scs = load_scenarios(ROOT / "scenarios" / "dev")
    a = [
        (r.id, r.blocked, r.rule_ids, [e["hash"] for e in r.trace])
        for r in (run_scenario(s, POLICY) for s in scs)
    ]
    b = [
        (r.id, r.blocked, r.rule_ids, [e["hash"] for e in r.trace])
        for r in (run_scenario(s, POLICY) for s in scs)
    ]
    assert a == b


def test_duplicate_ids_and_bad_metadata_rejected(tmp_path):
    f = tmp_path / "a.py"
    f.write_text(
        "from agentblackbox.scenario import attack, call\n"
        "SCENARIOS=[attack('d','c','t',(),[call('shell',command='ls')]),"
        "attack('d','c','t',(),[call('shell',command='ls')])]\n"
    )
    with pytest.raises(ValueError, match="duplicate"):
        load_scenarios(tmp_path)
    f.write_text(
        "from agentblackbox.scenario import Scenario\n"
        "SCENARIOS=[Scenario('d','c','t','maybe',())]\n"
    )
    with pytest.raises(ValueError, match="expected"):
        load_scenarios(tmp_path)
    f.write_text(
        "from agentblackbox.scenario import attack, call\n"
        "SCENARIOS=[attack('d','c','t',('LLM99',),[call('shell',command='ls')])]\n"
    )
    with pytest.raises(ValueError, match="OWASP"):
        load_scenarios(tmp_path)


def test_percentages_never_round_in_our_favour():
    assert bench.pct_down(2, 3) == "66.6%"  # truncated, not 66.7
    assert bench.pct_up(1, 3) == "33.4%"  # rounded up, not 33.3
    assert bench.pct_down(1, 1) == "100.0%" and bench.pct_up(0, 5) == "0.0%"
    assert bench.pct_down(0, 0) == "n/a"


def test_summary_math_and_lists():
    ok = run_scenario(attack("a", "c1", "t", (), [call("read_file", path="/etc/passwd")]), POLICY)
    miss = run_scenario(
        attack("b", "c1", "t", (), [call("read_file", path="workspace/README.md")]), POLICY
    )
    fp = run_scenario(benign("c", "bc", "t", [call("read_file", path="/etc/passwd")]), POLICY)
    fine = run_scenario(
        benign("d", "bc", "t", [call("read_file", path="workspace/README.md")]), POLICY
    )
    s = bench.summarize("unit", "default.yaml", [ok, miss, fp, fine])
    assert s["detection"]["detected"] == 1 and s["detection"]["total"] == 2
    assert s["detection"]["rate"] == "50.0%"
    assert s["false_positives"]["count"] == 1 and s["false_positives"]["rate"] == "50.0%"
    assert [m["id"] for m in s["misses"]] == ["b"]
    assert [m["id"] for m in s["false_positive_list"]] == ["c"]
    md = bench.to_markdown(s)
    assert "`b`" in md and "`c`" in md and "| c1 |" in md


def test_run_bench_writes_markdown_and_json(tmp_path):
    out = bench.run_bench(ROOT / "scenarios", "dev", ROOT / "policies" / "default.yaml", tmp_path)
    assert "Benchmark" in out
    data = json.loads((tmp_path / "bench_dev.json").read_text())
    assert data["attacks"] >= 50 and (tmp_path / "bench_dev.md").read_text() == out


def test_overhead_measurement_runs_and_reports_machine():
    res = bench.measure_overhead(POLICY, n=300)
    assert res["calls"] == 300 and res["guarded_median_us"] > 0
    assert "python" in res["machine"].lower()


def test_scenario_dataclass_is_frozen():
    s = Scenario("i", "c", "t", "allow", ())
    with pytest.raises(AttributeError):
        s.id = "x"
