# STATUS

## Done
- M0 scaffold.
- M1 recorder: hash chain, canonical JSON, HMAC-signed head file, redaction
  (`[REDACTED:<type>:<hash8>]`, also for base64/hex-wrapped secrets), `abb verify`.
  Tests cover edit, delete, reorder, insert, truncated tail, re-hashed chain, forged head.

- M2 guard + policy engine: `Guard.wrap`/`@guard.tool`, enforce/monitor, unknown-tool denial, YAML schema validation with rule/field errors, path/domain/secret/loop/flag rules, mock tools.

- M3 normalisation: URL (userinfo, lookalikes, IP literal forms, IPv6, case/dots, punycode/mixed script, backslash, bad schemes, encoded host), path (traversal, absolute, `~`, doubled/encoded separators), payload views (URL/base64/hex/nested/zero-width/NFKC/split-across-args), shell obfuscation analysis.

- M4 taint + canaries: session/value labels with k-gram fragment matching (survives copies and encodings), `session_has_all` trifecta, `call_has_taint`, deterministic canary planting, canary detection in raw/URL/hex/base64(any alignment)/base32/reversed/split forms; `canary.exfil` is a hard rule on outbound tools.

- M5 scenario harness + dev suite (93 attacks in 10 categories incl. 3 deliberate known-limitation attacks, 57 benign), `abb bench`, `abb overhead
abb replay trace.jsonl --policy policies/strict.yaml`, default/strict policies. Results in `docs/results/`.

- M6 policy frozen (commit `freeze policy for holdout`, tag `holdout-freeze`, hashes in `docs/FREEZE.json`, guarded by `tests/test_freeze.py`); then 10 holdout attacks + 5 benign written and run WITHOUT changing any rule. Holdout result: 4/10 attacks detected, 1/5 benign blocked (see `docs/results/bench_holdout.md`).

- M7 replay: `abb replay trace.jsonl --policy new.yaml [--json]`; verified that replaying every dev scenario trace under its own policy reproduces all live decisions. Recorder now also redacts reversed/base32/hex/base64 canary encodings.

## Not done
- M8..M9 (see the build brief).

## Known issues
- Holdout misses (by design of the current rules, not fixed because rules are frozen): `ho-a04` awk system(), `ho-a05` symlink creation, `ho-a06` zlib+base64 canary, `ho-a07` paraphrase via GET after hostile input (http_get is not a trifecta channel), `ho-a08` bare AWS secret key, `ho-a09` malicious git hook written inside the workspace.
- Holdout false positive: `ho-b02` (a harmless `echo` whose text contains a non-allow-listed URL trips `net.egress.shell_urls`).
- Dev misses: the three deliberate `known_limitations` attacks.

## Commands
```bash
pip install -e ".[dev]"
python -m pytest        # note: plain `pytest` may pick up a different interpreter
ruff check .
abb verify trace.jsonl
abb bench --suite dev --out docs/results
abb overhead
abb replay trace.jsonl --policy policies/strict.yaml
```
