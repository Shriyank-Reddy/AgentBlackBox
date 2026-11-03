# STATUS

## Done
- M0 scaffold.
- M1 recorder: hash chain, canonical JSON, HMAC-signed head file, redaction
  (`[REDACTED:<type>:<hash8>]`, also for base64/hex-wrapped secrets), `abb verify`.
  Tests cover edit, delete, reorder, insert, truncated tail, re-hashed chain, forged head.

## Not done
- M2..M9 (see the build brief).

## Known issues
- none yet

## Commands
```bash
pip install -e ".[dev]"
python -m pytest        # note: plain `pytest` may pick up a different interpreter
ruff check .
abb verify trace.jsonl
```
