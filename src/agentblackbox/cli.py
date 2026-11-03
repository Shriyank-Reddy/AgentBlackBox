"""The `abb` command line interface."""

from __future__ import annotations

import argparse
import sys

from . import __version__

COMMANDS = ("verify", "bench", "replay", "view", "demo")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="abb", description="AgentBlackBox: flight recorder and policy firewall for AI agents."
    )
    parser.add_argument("--version", action="version", version=f"abb {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")
    for name in COMMANDS:
        sub.add_parser(name, help=f"{name} (see docs)")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        return 0
    print(f"abb {args.command}: not implemented yet", file=sys.stderr)
    return 2
