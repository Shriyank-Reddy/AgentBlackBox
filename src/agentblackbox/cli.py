"""The `abb` command line interface."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

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


def _scenarios_dir(arg: str | None) -> Path:
    if arg:
        return Path(arg)
    here = Path("scenarios")
    return here if here.exists() else Path(__file__).resolve().parents[2] / "scenarios"


def _policies_dir() -> Path:
    here = Path("policies")
    return here if here.exists() else Path(__file__).resolve().parents[2] / "policies"


def cmd_bench(args: argparse.Namespace) -> int:
    from .bench import run_bench

    policy = Path(args.policy) if args.policy else _policies_dir() / "default.yaml"
    out = Path(args.out) if args.out else None
    print(run_bench(_scenarios_dir(args.scenarios), args.suite, policy, out))
    return 0


def cmd_overhead(args: argparse.Namespace) -> int:
    from .bench import measure_overhead
    from .policy import load_policy

    policy = Path(args.policy) if args.policy else _policies_dir() / "default.yaml"
    res = measure_overhead(load_policy(policy), n=args.calls)
    print(f"Overhead over {res['calls']} guarded read_file calls (trace written to a real file)")
    print(f"  machine:                {res['machine']}")
    print(f"  unguarded median:       {res['unguarded_median_us']} us")
    print(f"  guarded median / p95:   {res['guarded_median_us']} / {res['guarded_p95_us']} us")
    print(f"  added median / p95:     {res['added_median_us']} / {res['added_p95_us']} us")
    return 0


def cmd_replay(args: argparse.Namespace) -> int:
    import json

    from .policy import PolicyError, load_policy
    from .replay import format_report, replay_trace

    try:
        policy = load_policy(args.policy)
    except (PolicyError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    report = replay_trace(args.trace, policy, key=_key())
    if args.json:
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    else:
        print(format_report(report, args.trace, args.policy))
    return 0


def cmd_view(args: argparse.Namespace) -> int:
    from .viewer import render_report

    html = render_report(args.trace, key=_key())
    Path(args.output).write_text(html, encoding="utf-8")
    print(f"wrote {args.output} ({len(html)} bytes, self-contained)")
    return 0


def cmd_demo(args: argparse.Namespace) -> int:
    from .demo import run_demo

    policy = Path(args.policy) if args.policy else _policies_dir() / "default.yaml"
    print("\n".join(run_demo(policy, Path(args.out_dir))))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="abb", description="AgentBlackBox: flight recorder and policy firewall for AI agents."
    )
    parser.add_argument("--version", action="version", version=f"abb {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    p = sub.add_parser("verify", help="check a trace's hash chain and signed head")
    p.add_argument("trace")
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("bench", help="run the scenario benchmark and print a markdown report")
    p.add_argument("--suite", choices=["dev", "holdout", "both"], default="dev")
    p.add_argument("--policy", help="policy YAML (default: policies/default.yaml)")
    p.add_argument("--scenarios", help="scenarios directory (default: ./scenarios)")
    p.add_argument("--out", help="directory for bench_<suite>.json / .md files")
    p.set_defaults(func=cmd_bench)

    p = sub.add_parser("replay", help="re-evaluate a recorded trace under a different policy")
    p.add_argument("trace")
    p.add_argument("--policy", required=True, help="the new policy YAML")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    p.set_defaults(func=cmd_replay)

    p = sub.add_parser("view", help="render a trace as one self-contained HTML timeline")
    p.add_argument("trace")
    p.add_argument("-o", "--output", default="report.html")
    p.set_defaults(func=cmd_view)

    p = sub.add_parser("demo", help="run a poisoned-webpage attack story and write examples/")
    p.add_argument("--out-dir", default="examples")
    p.add_argument("--policy")
    p.set_defaults(func=cmd_demo)

    p = sub.add_parser("overhead", help="measure per-call overhead of the guard")
    p.add_argument("--calls", type=int, default=10_000)
    p.add_argument("--policy")
    p.set_defaults(func=cmd_overhead)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return 0
    return args.func(args)
