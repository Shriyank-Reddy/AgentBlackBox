"""The `abb` command line interface."""

from __future__ import annotations

import argparse
import os
import sys

from . import __version__
from .recorder import DEFAULT_HEAD_KEY, verify_trace

COMMANDS = ("verify", "bench", "replay", "view", "demo")


def _key() -> bytes:
    env = os.environ.get("ABB_HEAD_KEY")
    return env.encode() if env else DEFAULT_HEAD_KEY


def cmd_verify(args: argparse.Namespace) -> int:
    res = verify_trace(args.trace, key=_key())
    if res.ok:
        print(f"OK: {res.count} events, chain and signed head verified")
        return 0
    for err in res.errors:
        print(f"FAIL at seq {err.seq}: {err.reason}")
    return 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="abb", description="AgentBlackBox: flight recorder and policy firewall for AI agents."
    )
    parser.add_argument("--version", action="version", version=f"abb {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    p = sub.add_parser("verify", help="check a trace's hash chain and signed head")
    p.add_argument("trace")
    p.set_defaults(func=cmd_verify)
    _register_unimplemented(parser)
    return parser


def _register_unimplemented(parser: argparse.ArgumentParser) -> None:
    """Placeholder commands, replaced milestone by milestone."""
    sub = next(a for a in parser._actions if isinstance(a, argparse._SubParsersAction))
    for name in ("bench", "replay", "view", "demo"):
        if name not in sub.choices:
            sp = sub.add_parser(name, help=f"{name} (see docs)")
            sp.set_defaults(func=lambda a, n=name: _todo(n))


def _todo(name: str) -> int:
    print(f"abb {name}: not implemented", file=sys.stderr)
    return 2


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return 0
    return args.func(args)
