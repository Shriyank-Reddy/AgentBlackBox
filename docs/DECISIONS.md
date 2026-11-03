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
- IP-literal hosts, userinfo, backslashes, encoded hosts and control characters never match a domain allowlist | these forms have no legitimate use in an agent's URL and are the classic parser-differential tricks
- Backslash in a URL is treated as `/` (WHATWG behaviour) and flagged | browsers and urllib disagree, so the safest reading is "suspicious"
- Shell analysis treats `rm` as safe only when every target resolves under `workspace/`; unresolved `$VAR` targets count as unsafe | an unknown target must be assumed hostile
- Shell analysis is heuristic and static (no execution, no full shell grammar) | documented as a limitation; the shell tool is a mock anyway
- Secret-looking text split across several arguments is checked via a joined view | cheap defence against trivial argument splitting
- Canary check runs only for outbound tools (`outbound_tools`, default http_get/http_post/send_email/shell) | brief defines canary exfiltration as appearing in an outbound tool's arguments; writing a canary inside the workspace is not exfiltration
- Taint fragment matching uses hashed k-grams (k = `min_fragment`, default 16), skipping low-entropy grams; values shorter than k but >= 6 chars are matched whole | keeps "meaningful fragment" concrete and avoids tainting on whitespace or repeated characters
- Tool results are tainted by value as well as by label: a result that contains a fragment of an earlier tainted value inherits its label | models copy-through-a-file laundering
- Replay reuses the taint labels recorded in the trace instead of recomputing them | result contents are not stored in full, only a summary
