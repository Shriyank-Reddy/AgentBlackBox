# STATUS

All milestones M0 to M9 are complete. Stopped after M9 as instructed.

## Done
- **M0** scaffold, MIT licence, `abb --help`, pytest (85% coverage gate) and ruff config.
- **M1** hash-chained recorder, canonical JSON, HMAC-signed head file, redaction, `abb verify`
  (tests for edit, delete, reorder, insert, truncated tail, re-hashed chain, forged head).
- **M2** `Guard` (`wrap`, `@guard.tool`), enforce/monitor modes, unknown-tool denial, validated YAML
  policy schema (errors name rule and field), path/domain/secret/loop/flag rules, mock tools.
- **M3** normalisation: URL (userinfo, lookalikes, decimal/hex/octal/IPv6 IPs, case, trailing dots,
  punycode and mixed script, backslash, encoded host, bad schemes), paths (traversal, absolute, `~`,
  doubled and encoded separators), payload views (base64/hex/URL/nested/zero-width/NFKC/split args),
  shell de-obfuscation.
- **M4** taint tracking (session and value labels, fragment propagation), trifecta rule, canary
  planting and detection in many encodings (`canary.exfil` cannot be configured away).
- **M5** scenario harness, dev suite (93 attacks in 10 categories, 57 benign), `abb bench`.
- **M6** policy frozen (commit `freeze policy for holdout`, `docs/FREEZE.json`, `tests/test_freeze.py`),
  then 10 holdout attacks and 5 benign written and run without changing any rule.
- **M7** `abb replay` (verified: replaying all dev traces under the same policy reproduces every live decision).
- **M8** `abb view` (single offline HTML, light/dark, checked in headless Chromium) and `abb demo`
  (writes `examples/`).
- **M9** overhead measurement (`abb overhead`) and all docs.

## Results (from real runs; full tables in README and `docs/results/`)
- Dev: 90/93 attacks detected (96.7%), 0/57 benign blocked. The 3 misses are the deliberate
  `known_limitations` scenarios.
- Holdout: 4/10 attacks detected (40.0%), 1/5 benign blocked (20.0%).
- Overhead: see `docs/results/overhead.txt` (machine-dependent).
- Tests: 219 passing, about 97% line coverage, `ruff check` clean. Verified from a clean venv on
  Python 3.11 and 3.13 with `pip install -e ".[dev]"`.

## Known issues
- Holdout misses, left unfixed on purpose because rules were frozen before the holdout was written:
  `ho-a04` awk `system()`, `ho-a05` symlink creation, `ho-a06` zlib+base64 canary, `ho-a07` paraphrase
  via GET after hostile input (`http_get` is not a trifecta channel), `ho-a08` bare AWS secret key,
  `ho-a09` malicious git hook written inside the workspace.
- Holdout false positive: `ho-b02` (harmless `echo` whose text contains a non-allow-listed URL trips
  `net.egress.shell_urls`).
- Dev misses: `lim-01` (ROT13 canary), `lim-02` (paraphrased leak, no untrusted input),
  `lim-03` (canary split across two calls).
- The git tag `holdout-freeze` exists locally only; the git proxy rejected pushing the tag. The freeze
  is identified by the commit message `freeze policy for holdout` (021e9aa) and `docs/FREEZE.json`.
- Python 3.11 was only tested via `python3.11 -m venv` on this machine; no CI is configured.
- Head-file key is a demo constant unless `ABB_HEAD_KEY` is set.
- No tests are marked `xfail`; no problem needed more than three fix attempts.

## Commands
```bash
pip install -e ".[dev]"
python -m pytest                 # plain `pytest` may pick up a different interpreter
ruff check .
abb verify examples/demo_trace.jsonl
abb bench --suite both --out docs/results
abb replay examples/demo_trace.jsonl --policy policies/strict.yaml
abb demo && abb view examples/demo_trace.jsonl -o report.html
abb overhead > docs/results/overhead.txt
python scripts/build_readme.py   # rebuild README.md from docs/README.template.md + real outputs
```
