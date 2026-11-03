import json
import re
from pathlib import Path

from agentblackbox.cli import main
from agentblackbox.demo import run_demo
from agentblackbox.recorder import Recorder, verify_trace
from agentblackbox.viewer import build_view_data, render_report

ROOT = Path(__file__).resolve().parent.parent


def demo(tmp_path):
    story = run_demo(ROOT / "policies" / "default.yaml", tmp_path)
    return story, tmp_path / "demo_trace.jsonl", tmp_path / "demo_report.html"


def embedded(html):
    raw = re.search(r'<script id="abb-data" type="application/json">(.*?)</script>', html, re.S)
    return json.loads(raw.group(1))


def test_demo_story_is_stopped_by_the_trifecta(tmp_path):
    story, trace, report = demo(tmp_path)
    text = "\n".join(story)
    assert "DENIED" in text and "exfil.trifecta" in text
    assert "ALLOWED  write_file" in text  # legitimate work still goes through
    assert verify_trace(trace).ok
    assert report.exists()


def test_demo_is_deterministic(tmp_path):
    a = demo(tmp_path / "a")[1].read_text()
    b = demo(tmp_path / "b")[1].read_text()
    assert a == b


def test_report_is_self_contained_and_themed(tmp_path):
    _, trace, report = demo(tmp_path)
    html = report.read_text()
    assert "prefers-color-scheme: dark" in html and 'name="viewport"' in html
    # no external resources of any kind
    assert not re.search(r"<script[^>]+src=|<link[^>]+href=|@import|url\(\s*['\"]?https?:", html)
    assert "innerHTML" not in html
    data = embedded(html)
    assert data["integrity"]["ok"] and len(data["steps"]) == 8
    blob = json.dumps(data)
    assert "[REDACTED:" in blob or "customers" in blob
    assert "ABB_CANARY_" not in blob  # raw canaries never reach the report


def test_report_banner_data_when_chain_is_broken(tmp_path):
    _, trace, _ = demo(tmp_path)
    trace.write_text(trace.read_text().replace('"allow"', '"deny"', 1))
    data = build_view_data(trace)
    assert not data["integrity"]["ok"] and data["integrity"]["errors"][0]["seq"] == 0
    html = render_report(trace)
    assert embedded(html)["integrity"]["errors"][0]["seq"] == 0


def test_hostile_trace_content_cannot_break_out_of_the_page(tmp_path):
    path = tmp_path / "evil.jsonl"
    rec = Recorder(path, session_id="s")
    rec.append(
        kind="call",
        tool="x",
        args={"a": "</script><img src=x onerror=alert(1)><!--"},
        decision="allow",
    )
    html = render_report(path)
    # exactly two script blocks (data + code): the payload's </script> was neutralised
    assert html.count("</script") == 2 and "<img src=x" not in html
    assert embedded(html)["steps"][0]["call"]["args"]["a"].startswith("</script>")


def test_view_handles_garbage_lines(tmp_path):
    path = tmp_path / "t.jsonl"
    rec = Recorder(path, session_id="s")
    rec.append(kind="call", tool="x", args={}, decision="allow")
    path.write_text(path.read_text() + "garbage\n")
    assert not build_view_data(path)["integrity"]["ok"]


def test_cli_view_and_demo(tmp_path, capsys):
    assert main(["demo", "--out-dir", str(tmp_path)]) == 0
    assert "exfil.trifecta" in capsys.readouterr().out
    out = tmp_path / "r.html"
    assert main(["view", str(tmp_path / "demo_trace.jsonl"), "-o", str(out)]) == 0
    assert out.exists() and "self-contained" in capsys.readouterr().out
