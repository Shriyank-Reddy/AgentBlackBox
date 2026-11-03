# STATUS

## Done
- M0 scaffold.
- M1 recorder: hash chain, canonical JSON, HMAC-signed head file, redaction
  (`[REDACTED:<type>:<hash8>]`, also for base64/hex-wrapped secrets), `abb verify`.
  Tests cover edit, delete, reorder, insert, truncated tail, re-hashed chain, forged head.

- M2 guard + policy engine: `Guard.wrap`/`@guard.tool`, enforce/monitor, unknown-tool denial, YAML schema validation with rule/field errors, path/domain/secret/loop/flag rules, mock tools.

- M3 normalisation: URL (userinfo, lookalikes, IP literal forms, IPv6, case/dots, punycode/mixed script, backslash, bad schemes, encoded host), path (traversal, absolute, `~`, doubled/encoded separators), payload views (URL/base64/hex/nested/zero-width/NFKC/split-across-args), shell obfuscation analysis.

- M4 taint + canaries: session/value labels with k-gram fragment matching (survives copies and encodings), `session_has_all` trifecta, `call_has_taint`, deterministic canary planting, canary detection in raw/URL/hex/base64(any alignment)/base32/reversed/split forms; `canary.exfil` is a hard rule on outbound tools.

- M5 scenario harness + dev suite (93 attacks in 10 categories incl. 3 deliberate known-limitation attacks, 57 benign), `abb bench`, `abb overhead`, default/strict policies. Results in `docs/results/`.

- M6 (part 1) policy and rule code frozen; hashes in `docs/FREEZE.json`, guarded by `tests/test_freeze.py`.

## Not done
- M6 (part 2) holdout scenarios, M7..M9 (see the build brief).

## Known issues
- none yet

## Commands
```bash
pip install -e ".[dev]"
python -m pytest        # note: plain `pytest` may pick up a different interpreter
ruff check .
abb verify trace.jsonl
abb bench --suite dev --out docs/results
abb overhead
```
