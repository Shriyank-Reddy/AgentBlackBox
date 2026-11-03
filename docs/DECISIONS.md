# Decisions

One line each: decision | reason.

- decision: LICENSE holder set to 'Shriyank Reddy Singireddy' | reason: brief specifies the full name
- secrets.py added as its own module | the same patterns drive redaction (recorder) and the policy secret rule, so they must live in one place
- Head file is `<trace>.head`, HMAC-SHA256 over `count:last_hash` with a demo key (override via `ABB_HEAD_KEY`) | brief asks for a "signed" head; real deployments must keep the key off the agent's machine
- Recorder refuses to overwrite an existing trace unless `overwrite=True` | evidence should not vanish silently
- Each tool call writes two events: a `call` event (decision, before running) and a `result` event (summary) | matches the pipeline "record, run, record result"; a crash mid-tool still leaves the decision on record
- Missing head file makes `verify` fail | without it truncation cannot be ruled out
- Use `python -m pytest` in docs | a stray `pytest` script on PATH may belong to another interpreter
- `default: deny` means "tools not listed under `tools:` are denied" (rule id `policy.unknown_tool`) | gives the brief's "unknown tools denied" a concrete, testable meaning
- Rules are `deny_if` or `flag_if` conditions (never both) | keeps each rule single-purpose; the engine combines them (any deny wins)
- Allow-list domain entries match exactly; `*.example.com` matches subdomains only | subdomain wildcards are an explicit, reviewable choice
- Loop counting uses redacted args and counts every attempt, including denied ones | a looping agent is a loop whether or not calls are denied, and replay can recompute the same key from a trace
- Filesystem tools use an in-memory dict keyed by virtual absolute paths, resolved with the firewall's own `normalize_path` | no real disk access, and guard and tool agree on what a path means
- Extra modules beyond the layout (`secrets.py`, `clock.py`, `mocktools.py`, later `scenario.py`, `bench.py`) | each has one clear job; avoids dumping grounds
