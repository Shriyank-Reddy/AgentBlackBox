"""Build README.md from docs/README.template.md by pasting real command output.

Run from the repository root after `abb bench --suite both --out docs/results`,
`abb overhead > docs/results/overhead.txt` and `abb demo`.
"""

import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def run(*cmd: str) -> str:
    return subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, check=True).stdout.rstrip()


def main() -> None:
    overhead = read("docs/results/overhead.txt").rstrip()
    machine = next(
        line.split(":", 1)[1].strip() for line in overhead.splitlines() if "machine" in line
    )
    values = {
        "DEMO": run("abb", "demo", "--out-dir", "examples"),
        "QUICKSTART": read("examples/quickstart.py").rstrip(),
        "QUICKSTART_OUT": run("python", "examples/quickstart.py"),
        "DEV": read("docs/results/bench_dev.md"),
        "HOLDOUT": read("docs/results/bench_holdout.md"),
        "OVERHEAD": overhead,
        "MACHINE": f"{machine} (Intel Xeon @ 2.10GHz, 4 vCPUs, container)",
        "REPLAY": read("docs/results/replay_demo_strict.txt").rstrip(),
    }
    text = read("docs/README.template.md")
    for key, value in values.items():
        text = text.replace("{{" + key + "}}", value)
    (ROOT / "README.md").write_text(text, encoding="utf-8")


if __name__ == "__main__":
    main()
