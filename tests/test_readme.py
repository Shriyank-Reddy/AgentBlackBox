"""The README must contain exactly what a fresh run produces."""

from pathlib import Path

from agentblackbox import bench
from agentblackbox.cli import main

ROOT = Path(__file__).resolve().parent.parent
README = (ROOT / "README.md").read_text(encoding="utf-8")


def fresh(suite: str, tmp_path: Path) -> str:
    bench.run_bench(ROOT / "scenarios", suite, ROOT / "policies" / "default.yaml", tmp_path)
    return (tmp_path / f"bench_{suite}.md").read_text(encoding="utf-8")


def test_benchmark_tables_match_a_fresh_run(tmp_path):
    assert fresh("dev", tmp_path) in README
    assert fresh("holdout", tmp_path) in README


def test_committed_results_match_a_fresh_run(tmp_path):
    for suite in ("dev", "holdout"):
        assert (ROOT / "docs" / "results" / f"bench_{suite}.md").read_text() == fresh(
            suite, tmp_path
        )


def test_quickstart_in_readme_is_the_real_example():
    assert (ROOT / "examples" / "quickstart.py").read_text().rstrip() in README


def test_overhead_block_is_pasted_verbatim():
    assert (ROOT / "docs" / "results" / "overhead.txt").read_text().rstrip() in README


def test_demo_example_trace_still_verifies(capsys):
    assert main(["verify", str(ROOT / "examples" / "demo_trace.jsonl")]) == 0
