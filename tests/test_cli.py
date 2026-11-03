import pytest

from agentblackbox.cli import COMMANDS, build_parser, main


def test_help_lists_all_commands(capsys):
    with pytest.raises(SystemExit) as exc:
        build_parser().parse_args(["--help"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    for name in COMMANDS:
        assert name in out


def test_no_args_prints_help(capsys):
    assert main([]) == 0
    assert "abb" in capsys.readouterr().out


def test_verify_command(tmp_path, capsys):
    from agentblackbox.recorder import Recorder

    path = tmp_path / "t.jsonl"
    rec = Recorder(path, session_id="s")
    rec.append(kind="call", tool="t", args={}, decision="allow")
    rec.append(kind="call", tool="t", args={}, decision="allow")
    assert main(["verify", str(path)]) == 0
    assert "OK" in capsys.readouterr().out
    path.write_text(path.read_text().replace('"allow"', '"deny"', 1))
    assert main(["verify", str(path)]) == 1
    assert "seq 0" in capsys.readouterr().out


def test_bench_and_overhead_commands(tmp_path, capsys):
    assert main(["bench", "--suite", "dev", "--out", str(tmp_path)]) == 0
    assert "All attacks" in capsys.readouterr().out
    assert (tmp_path / "bench_dev.json").exists()
    assert main(["overhead", "--calls", "200"]) == 0
    assert "added median" in capsys.readouterr().out
