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
