# AgentBlackBox

**A tamper-evident flight recorder and policy firewall for AI agents: every tool call is checked against a YAML policy, tracked for data origin, watched for planted canary secrets, and written to a hash-chained log.**

Everything here is a mock: no network, no paid APIs, no LLM, no real shell or filesystem access. "Agents" are scripted lists of tool calls, so every test and benchmark is deterministic and free.

## 30-second demo

```bash
pip install -e ".[dev]"
abb demo                       # runs the attack story, writes examples/
abb verify examples/demo_trace.jsonl
open examples/demo_report.html # or just double-click it; it works offline
```

`abb demo` plays out one realistic story: an agent triaging a GitHub issue reads a page with a hidden prompt injection, is told to post a private customer file, and is stopped by the **trifecta rule** (private data + untrusted content + an outbound channel in one session). It also tries a fallback email to the attacker (denied) and then does its legitimate work (allowed).

The report (`examples/demo_report.html`, committed) is a single offline HTML file that is readable in light and dark mode. It shows a vertical timeline of tool calls with **allow / flag / deny badges**, the **rules that fired**, **taint labels as coloured chips**, redacted values shown as visible `[REDACTED:type:hash]` marks, and a **chain-integrity banner** (green when `abb verify` passes; red with the broken `seq` when it fails).

Demo output:

```text
{{DEMO}}
```

## Install and quickstart

Python 3.11+. Runtime dependency: `pyyaml`. Dev: `pytest`, `pytest-cov`, `ruff`.

```bash
pip install -e ".[dev]"
python -m pytest        # 85% coverage gate is enforced
ruff check .
```

| Command | What it does |
|---|---|
| `abb verify trace.jsonl` | Check the hash chain and signed head; name the first broken `seq`. |
| `abb bench --suite dev\|holdout\|both [--out docs/results]` | Run the scenario benchmark; print markdown, write JSON + markdown. |
| `abb replay trace.jsonl --policy policies/strict.yaml` | Re-evaluate a recording under another policy and diff the decisions. |
| `abb view trace.jsonl -o report.html` | Render a trace as a self-contained HTML timeline. |
| `abb demo` | Run the poisoned-webpage story and write `examples/`. |
| `abb overhead` | Measure per-call overhead of the guard. |

### Minimal example: wrapping two tools

`examples/quickstart.py` (run from the repository root):

```python
{{QUICKSTART}}
```

Output:

```text
{{QUICKSTART_OUT}}
```

## Benchmark results

All numbers below are pasted from real runs (`abb bench --suite both --out docs/results` and `abb overhead`); a test fails if this README drifts from a fresh run. The dev and holdout suites are reported **separately** and never merged.

- **Dev suite** (`scenarios/dev/`): written while building the rules.
- **Holdout suite** (`scenarios/holdout/`): written *after* the policy was frozen (commit `freeze policy for holdout`; hashes in `docs/FREEZE.json`, checked by `tests/test_freeze.py`) and run without changing any rule.

### Dev

{{DEV}}
### Holdout

{{HOLDOUT}}
### Rule changes after the freeze

**No detection rule or detection code was changed after the holdout was written or run.** `tests/test_freeze.py` verifies the hashes of the policy and the detection modules. Before the freeze, one change was made *because of a dev result*: the benign lookalike `bn-lk-03` (`api_key = YOUR_API_KEY_HERE`) was a false positive, so placeholder values are now ignored by the generic-secret pattern. After the freeze only non-detection code changed (replay, viewer, demo, CLI, recorder performance and canary-encoding redaction). The holdout misses and false positive are listed in `STATUS.md` and explained in `docs/THREAT_MODEL.md`; they were not fixed.

### Overhead

```text
{{OVERHEAD}}
```

Measured over 10,000 guarded mock `read_file` calls, each writing a real trace file (two events per call, head file updated every event), compared with the same calls unguarded. Machine: {{MACHINE}}. Timing is machine- and run-dependent, so unlike the benchmark tables it will not match to the digit on another run.

### Replay example

```bash
abb replay examples/demo_trace.jsonl --policy policies/strict.yaml
```

```text
{{REPLAY}}
```

## How it works

```
agent ──► Guard.call ──► normalise ──► taint ──► canary scan ──► policy ──► record ──► tool ──► record result ──► taint result
                                                                       └─ deny (enforce): raise PolicyViolation, tool never runs
```

- **Recorder.** One JSON object per line; `hash = sha256(canonical_json(event) + prev_hash)`; a signed head file stores count and last hash so truncation is detectable. Secrets and canaries are redacted before writing.
- **Policy.** YAML rules (`deny_if` / `flag_if`) over normalised paths, URLs, decoded text views, shell analysis and taint labels. Unknown tools are denied. See `docs/POLICY.md`.
- **Normalisation.** URLs are parsed like a browser (userinfo tricks, IP literal forms, punycode, trailing dots); paths are canonicalised against the sandbox; payloads are also checked in base64/hex/URL-encoded form; shell strings are de-obfuscated.
- **Taint.** `private_data` and `untrusted_content` labels attach to the session and to returned values; fragments propagate. The **trifecta** rule is the flagship.
- **Canaries.** Planted `ABB_CANARY_…` fakes; any appearance in an outbound call, in any encoding, is always denied.
- **Replay / viewer.** Counterfactual policy diff and a one-file HTML report.

Details: `docs/ARCHITECTURE.md`, `docs/THREAT_MODEL.md`, `docs/LEARNING.md` (study guide with 15 interview questions).

## Limitations (please read)

- **The scenarios were written by the same author as the rules.** The dev numbers are optimistic by construction; the holdout was written after the freeze, but by the same person who knew how the rules work, so it is not an independent evaluation. Compare the two tables above: the gap between them is the honest signal.
- **Scripted agents are not real LLM agents.** Real models paraphrase, adapt to refusals, chain tools unpredictably and can be steered by content a fixed script never anticipates. Nothing here measures model behaviour.
- **Everything is a mock.** A policy check is not a sandbox. Wrapping real tools would need OS-level isolation as well.
- **What it would not catch** (measured misses are in the tables above): paraphrased or summarised leaks when the session lacks the full trifecta; data sent through channels the trifecta rule does not cover (for example a GET query string); transforms it does not decode (ROT13, compression, encryption, cross-call reassembly); credentials with no recognisable format; shell commands outside its heuristics (`awk system()`, symlinks, `mv`, `tee`); dangerous writes *inside* the workspace such as git hooks; loops whose arguments keep changing; attacker-writable content on allow-listed hosts; and trace forgery by someone holding the head-file key (the default key is a demo constant).
- **False positives exist.** For example a harmless shell `echo` whose text mentions a non-allow-listed URL is blocked. Redaction is pattern-based, so private data that matches no pattern can appear in recorded arguments.

## Repository map

```
src/agentblackbox/   recorder, secrets, normalize, policy, guard, taint, canary, replay, viewer,
                     mocktools, scenario, bench, demo, clock, cli
policies/            default.yaml, strict.yaml
scenarios/dev/       attacks/ and benign/ used while building rules
scenarios/holdout/   written after the freeze
docs/                ARCHITECTURE, THREAT_MODEL, POLICY, DECISIONS, LEARNING, results/
examples/            demo trace, head file, HTML report, quickstart.py
```

MIT licence, Shriyank Reddy Singireddy.
