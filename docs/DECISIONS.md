# Decisions

One line each: decision | reason.

- decision: LICENSE holder set to 'Shriyank Reddy Singireddy' | reason: brief specifies the full name
- secrets.py added as its own module | the same patterns drive redaction (recorder) and the policy secret rule, so they must live in one place
- Head file is `<trace>.head`, HMAC-SHA256 over `count:last_hash` with a demo key (override via `ABB_HEAD_KEY`) | brief asks for a "signed" head; real deployments must keep the key off the agent's machine
- Recorder refuses to overwrite an existing trace unless `overwrite=True` | evidence should not vanish silently
- Each tool call writes two events: a `call` event (decision, before running) and a `result` event (summary) | matches the pipeline "record, run, record result"; a crash mid-tool still leaves the decision on record
- Missing head file makes `verify` fail | without it truncation cannot be ruled out
- Use `python -m pytest` in docs | a stray `pytest` script on PATH may belong to another interpreter
