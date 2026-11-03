# Learning guide

Written for a computer-science student who has to explain this project in an interview. Read
the modules in this order; each section says what the module does, the one idea to understand,
the function to read first, and what would break without it.

The one-sentence version: *AgentBlackBox sits between an AI agent and its tools, checks every
call against a policy (with careful input normalisation and data-flow tracking), and writes a
hash-chained log so tampering shows.* Everything is a mock and fully deterministic.

---

## 1. `recorder.py`: the tamper-evident log

- **What it does.** Writes one JSON line per event, each containing the hash of the previous
  line. `verify_trace` re-computes everything and tells you the first `seq` that is wrong.
- **Key idea: hash chains.** `hash = sha256(canonical_json(event) + prev_hash)`. Change any past
  event and its hash changes, which no longer matches the next event's `prev_hash`. To hide a
  change you must recompute every later hash, which is easy for an attacker, so we add a **signed
  head file** (event count + last hash + HMAC). Without the key they cannot make a matching head.
  A chain alone cannot detect that someone deleted the *last* lines; the head can.
- **Key idea: canonical JSON.** Hashing needs one exact byte string per event. `json.dumps` with
  sorted keys, no spaces and ASCII-only makes the same data always serialise identically.
- **Read first:** `verify_trace`.
- **If removed:** there is no evidence the log is genuine; an incident review cannot trust it.

## 2. `secrets.py`: what counts as a secret

- **What it does.** Regexes for common credential formats plus a redactor that replaces matches
  with `[REDACTED:<type>:<8 hex of sha256>]`, also for secrets hidden inside base64/hex blobs.
- **Key idea.** The hash fingerprint lets an analyst see that two redactions were the *same*
  value without seeing it. The same pattern list drives redaction and the policy rule, so the
  log never stores something the firewall calls a secret.
- **Read first:** `redact_text`.
- **If removed:** secrets would be written into the trace, turning the flight recorder into a
  credential store.

## 3. `normalize.py`: where the real difficulty lives

- **What it does.** Turns attacker-controlled strings into canonical facts: the real host of a
  URL, the real location of a path, every decoded reading of a payload, the dangerous patterns in
  a shell string.
- **Key idea: parser differentials.** Security checks fail when the checker reads a string
  differently from the thing that uses it. `https://allowed.com@evil.com` *looks* like
  allowed.com, but the host is evil.com (everything before the last `@` is a username).
  `2130706433` is `127.0.0.1`. `%2e%2e%2f` is `../`. The fix is to normalise first and compare
  canonical values, and to treat ambiguity (userinfo, backslashes, IP literals) as suspicious.
- **Read first:** `normalize_url`.
- **If removed:** every egress, path and secret rule can be bypassed with encoding tricks. This is
  the module most worth being able to discuss in depth.

## 4. `policy.py`: rules as data

- **What it does.** Loads YAML, validates it with readable errors, compiles each condition into a
  small function, and evaluates a call to `allow`, `deny` or `flag`.
- **Key idea.** Policy-as-data separates *what is allowed* (reviewable by a human, replayable)
  from *how it is enforced*. Evaluation order is fixed: canary rule, unknown tool, then user rules;
  any deny wins.
- **Read first:** `Policy.evaluate`, then `compile_condition`.
- **If removed:** you would have hard-coded checks scattered through the code and no way to
  replay history against a new rule set.

## 5. `guard.py`: the interceptor

- **What it does.** Wraps tool functions. Each call goes: normalise, taint, canary scan, policy,
  record, run (only if allowed), record result, propagate taint.
- **Key idea: complete mediation.** The agent never holds the raw tool, only the wrapped one, so
  there is no path around the checks. Recording the decision *before* running the tool means a
  crash cannot erase it.
- **Read first:** `Guard.call`.
- **If removed:** nothing enforces anything.

## 6. `taint.py`: following data through a session

- **What it does.** Labels data as `private_data` or `untrusted_content` by where it came from,
  and remembers returned text so a later call that contains a fragment of it inherits the label.
- **Key idea: taint tracking.** Instead of asking "does this argument look like a secret?", ask
  "did this argument *come from* somewhere private?". Matching is done on hashed 16-character
  windows (k-grams), so it survives partial copies and (via decoded views) re-encoding.
- **Read first:** `TaintTracker.observe_result`.
- **If removed:** the flagship trifecta rule has no labels to look at, and paraphrase-free leaks
  of non-pattern data (customer rows) go unnoticed.

## 7. `canary.py`: tripwires

- **What it does.** Generates deterministic fake credentials, plants them in the mock sandbox,
  and detects them in outbound arguments in many encodings.
- **Key idea.** A canary has no legitimate use, so its appearance is *certain* evidence rather than
  a statistical guess. This turns a fuzzy detection problem into a precise one.
- **Read first:** `variants` (note the base64 alignment trick: the same bytes encode differently
  depending on their offset, so we search for the three stable middles).
- **If removed:** you lose the one detector with zero false positives.

## 8. `replay.py`: counterfactuals

- **What it does.** Re-evaluates a recorded trace under a different policy and diffs the decisions.
- **Key idea.** Because the policy is data and the trace records everything the policy needs
  (args, taint labels), you can ask "what would the stricter policy have blocked last week?"
  without re-running anything. Limits: redacted arguments, taint taken from the trace.
- **Read first:** `replay_events`.
- **If removed:** you could not evaluate a policy change against real history before deploying it.

## 9. `viewer.py`: the human interface

- **What it does.** One offline HTML file: timeline, badges, taint chips, redactions, integrity
  banner.
- **Key idea.** Logs are only useful if people can read them. Also: the viewer renders
  attacker-influenced data, so it must not execute it (no `innerHTML`; JSON is embedded inertly
  with `<` escaped).
- **Read first:** `render_html`.
- **If removed:** the trace is still correct but hard to review.

## 10. `scenario.py`, `bench.py`, `mocktools.py`, `clock.py`: honest measurement

- **What they do.** Scenarios are scripted tool-call lists with metadata; the bench runs them
  against a fresh guard and reports detection per category, false positives, and a "right reason"
  check. Mock tools never touch the real system; clocks and seeds are injected.
- **Key idea.** Numbers are only meaningful if they are reproducible and not tuned on the test
  data. Hence the dev/holdout split, the freeze commit, truncated detection rates and rounded-up
  false-positive rates, and keeping known failures in the suite.
- **Read first:** `run_scenario`, then `summarize`.
- **If removed:** you could claim anything; with it, every README number can be regenerated.

## 11. `cli.py` and `demo.py`

`cli.py` is argument parsing glue (`verify`, `bench`, `replay`, `view`, `demo`, `overhead`).
`demo.py` is a story you can show in 30 seconds. Read `run_demo` to see the pipeline's behaviour
end to end.

---

## Fifteen interview questions

**1. What problem does this solve?**
Agents act through tools, and an attacker who controls text the agent reads can steer those
tools. This project mediates every tool call with a policy and records it tamper-evidently, so
harmful actions are blocked and the history is trustworthy.

**2. How does the hash chain detect tampering, and what can it not detect?**
Each event stores the hash of its predecessor, so editing, deleting, inserting or reordering any
event breaks a link, and `verify` reports the first bad `seq`. A chain alone cannot detect that
the *tail* was cut off, nor a full re-hash by someone who can rewrite the whole file. The
HMAC-signed head (count + last hash) covers both, provided the key stays secret.

**3. Why canonical JSON?**
Hashes are over bytes, so the same event must always serialise to exactly the same bytes. Sorted
keys, no whitespace and ASCII escaping remove every degree of freedom.

**4. Why is URL checking hard? Give examples.**
Different parsers disagree. `https://allowed.com@evil.com` has host evil.com; `allowed.com.evil.com`
is a subdomain of evil.com; `http://2130706433` is 127.0.0.1; punycode and mixed scripts make
lookalike names; `%2e` in a host decodes to a dot. The fix is to parse like a browser, canonicalise
(lowercase, trailing dots, IP forms), compare exact hosts, and refuse ambiguous forms.

**5. What is taint tracking here?**
Data gets a label from its origin (`private_data`, `untrusted_content`). Labels attach to the
session and to returned text; later calls whose arguments contain a 16-character fragment of
that text inherit the label. It tracks origin instead of guessing from content.

**6. Explain the lethal trifecta and why the rule is session-level.**
Data theft needs private data, untrusted instructions and an outbound channel together. Removing
any leg makes the attack impossible. The rule denies outbound calls once a session has both
labels, even if the arguments look harmless, because an attacker can paraphrase or encode data
so content matching fails.

**7. Why plant canaries when you already have secret patterns?**
Patterns guess; canaries are certain. A planted fake has no legitimate reason to leave, so seeing
it (in any encoding) outbound is proof of exfiltration with essentially no false positives.

**8. How do you detect a base64-encoded canary inside a larger blob?**
Base64 output depends on the byte offset of the data, so I precompute the canary's encoding at
three alignments and keep only the middle characters that do not depend on neighbouring bytes,
then search for those substrings. Whole-token decoding handles the other cases.

**9. What do `enforce` and `monitor` mean, and why have both?**
Enforce blocks denied calls and raises `PolicyViolation`. Monitor never blocks but records what
would have been denied, which lets you roll out a policy and measure false positives safely.

**10. Why record the decision before running the tool?**
If the tool crashes or hangs, the evidence that it was allowed (or denied) is already in the
chain. That is why each call produces a `call` event and a later `result` event.

**11. How do you keep secrets out of the log, yet still replay it?**
Redaction replaces secrets with `[REDACTED:type:hash8]`. The marker is itself recognised as "a
secret was here" when the trace is re-evaluated, and the recorded taint labels stand in for the
original data. I tested that replaying every dev scenario under its own policy reproduces the
live decisions.

**12. How did you evaluate it honestly?**
Scripted agents make runs deterministic and free. I tuned rules on a dev suite, froze the policy
in a commit and a hash file, then wrote a separate holdout and ran it without changing rules.
Detection rates are truncated and false-positive rates rounded up. Known failures stay in the suite.
Dev: 90/93 detected, holdout: 4/10, which shows how much of the dev score came from author bias.

**13. What are the biggest limitations?**
Scenarios and rules share an author; scripted agents are not LLMs; paraphrased leaks without the
full trifecta, transforms like ROT13/compression, bare unrecognisable secrets, many shell
commands, and dangerous writes inside the workspace all pass. See THREAT_MODEL.md.

**14. How would you extend it to real tools?**
Keep the guard and policy, but run the real tools in an OS sandbox (container, seccomp, a
network namespace), because a policy check is not isolation. Move the HMAC key to a separate
service, and add content classifiers as an additional signal, not a replacement.

**15. How do you know the viewer is not itself a vulnerability?**
Tool arguments are attacker-influenced. The report embeds the trace as inert JSON with `<`, `>`
and `&` escaped and builds the DOM with `textContent` only, never `innerHTML`; a test feeds in a
`</script><img onerror=...>` payload and checks it cannot break out.
