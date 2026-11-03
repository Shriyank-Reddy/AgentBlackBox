# Threat model

## What is being protected

An AI agent holds tools (files, shell, web, email). The risk is that the agent is *steered*
by something other than its operator (text in a web page, an email, an issue) into using those
tools harmfully, or simply malfunctions. AgentBlackBox sits between the agent and the tools,
decides every call, and keeps a tamper-evident record.

## Attacker model

- **Content attacker.** Controls text the agent will read (web pages, issues, emails, files in
  an inbox) but not the agent's code, the policy, or the machine. Goal: make the agent leak
  data, run destructive commands or reach attacker infrastructure. This is the main model.
- **Confused or looping agent.** No attacker; the agent repeats calls or wanders. Goal of the
  defence: bound the damage (loop guard, call budget, unknown-tool denial).
- **Log tamperer.** Someone with write access to the trace file *after* the fact who wants to
  hide or alter what happened, but who does not hold the head-file key.

## In scope

Policy decisions on every tool call; path, URL and shell normalisation; secret and canary
detection in arguments (including common encodings); data-flow tracking across a session;
tamper evidence for the recorded trace; counterfactual replay under another policy.

## Out of scope (not defended)

- A malicious or compromised *operator*, policy file or host. Anyone who can edit the policy,
  the code, or hold the HMAC key can defeat everything here.
- Real tool execution safety. In this repository all tools are mocks; wrapping real tools
  would additionally need OS-level sandboxing. A policy check is not a sandbox.
- Model-level defences (training, prompt hardening, content classifiers). There is no
  prompt-injection *detector*; the design assumes injection will sometimes succeed and limits
  what a successful injection can do.
- Confidentiality of the trace itself. Redaction is pattern-based: private data that matches no
  pattern (a customer name, a card number) can appear in recorded arguments.
- Side channels, timing, steganography, and any exfiltration that carries no recognisable
  fragment of the data (see below).

## Why each rule exists

| Rule | Why |
|---|---|
| `fs.escape.read` / `fs.escape.write` | Agents are given a workspace; reads and writes outside it (`/etc/passwd`, `~/.ssh`, `../..`) are the classic escape. Paths are normalised first so `%2e%2e%2f`, `~`, backslashes and doubled slashes do not evade it. |
| `net.egress.allowlist` | Network access is the exfiltration channel. A short allow-list beats a block-list. URLs are parsed like a browser would, because `https://allowed.com@evil.com`, `allowed.com.evil.com`, `2130706433` and punycode lookalikes all fool naive string matching. |
| `net.egress.shell_urls` | `curl` in a shell command is the same channel through a different tool. |
| `net.email.recipients` | Mail is an exfiltration channel that is not a URL. |
| `shell.dangerous` | Destructive (`rm -rf /`, `dd`, fork bomb), remote-code (`curl \| bash`, decoded payloads) and persistence/reverse-shell patterns, after undoing quoting, variables and encodings. |
| `secrets.in_outbound_args` | Credentials in outbound arguments are leaks regardless of destination. Encoded forms are checked too. |
| `exfil.private_fragment` | If an outbound argument contains a recognisable piece of data the agent read from a private location, it is leaving. Catches leaks to an allow-listed host (for example a public gist on an allowed domain). |
| `exfil.trifecta` | See below. |
| `loop.guard`, `budget.calls` | Unbounded consumption: identical calls repeated, or simply too many calls. |
| `canary.exfil` (built in) | A canary is fake bait. Its appearance in an outbound call is certain evidence of exfiltration, so it is always denied and cannot be configured away. |
| `policy.unknown_tool` (built in) | Excessive agency: the agent may use only tools the operator granted. |
| `review.private_read` (flag) | Reading private data is legitimate but worth surfacing in review. |

## The lethal trifecta (flagship rule)

An agent is exploitable for data theft when three things meet in one session:

1. **Private data**: it has read something confidential.
2. **Untrusted content**: it has read text an outsider could have written (a web page, an
   inbox file), which may contain instructions.
3. **An outbound channel**: it can send data somewhere (`http_post`, `send_email`).

With any one leg missing there is no complete attack: no secrets, nothing to steal; no
untrusted input, nobody to inject instructions; no outbound tool, nowhere to send it. So the
rule `exfil.trifecta` denies an outbound call when the *session* has both labels, **even if the
call's arguments contain nothing recognisable**. That matters because an injected agent can
paraphrase, summarise or re-encode data to defeat fragment matching; the trifecta rule does not
depend on spotting the data, only on the session's history. The cost is that it can refuse
benign work once both labels are present; the benign suite includes sessions that touch only
one or two legs to show the common cases stay allowed.

## What this does not catch (be honest)

These are measured gaps, not hypotheticals. They appear as misses in the dev suite
(`known_limitations`) and the holdout suite (see the README tables).

- **Paraphrased exfiltration without the full trifecta.** Private data summarised in the
  agent's own words and posted to an allow-listed host, with no untrusted input in the session
  (`lim-02`). No 16-character fragment survives, and the trifecta needs both labels.
- **Non-trifecta channels.** `exfil.trifecta` guards `http_post` and `send_email`. Data
  smuggled through a `http_get` query string after hostile input is only caught if a fragment
  matches (`ho-a07`).
- **Encodings and transforms we do not decode.** ROT13 (`lim-01`), compressed-then-encoded
  payloads (`ho-a06`), base64 split across lines or calls (`lim-03`), anything encrypted.
- **Credentials with no recognisable shape.** A bare AWS secret access key (`ho-a08`) or an
  opaque bearer token matches no pattern; only canaries and taint would catch them.
- **Shell coverage is a static heuristic.** `awk 'BEGIN{system(...)}'` (`ho-a04`), `mv`,
  `tee`, `ln -s` symlink creation (`ho-a05`) and many other commands are not analysed.
- **Dangerous writes inside the workspace.** Writing a git hook or CI file that later runs
  attacker code (`ho-a09`) passes the path rule.
- **Near-identical loops.** A loop whose arguments change each time evades `loop.guard` until
  the call budget is hit.
- **Allow-listed hosts the attacker controls.** An allowed domain that also hosts
  attacker-writable content (a public gist) is a channel the allow-list cannot close.
- **Cross-call reassembly.** Detection is per call (plus the session's labels); fragments sent
  across several calls are not reassembled.
- **False positives.** Text that merely *mentions* a non-allow-listed URL inside a shell
  command is blocked (`ho-b02`).
- **Trace integrity relies on a key.** The head file's HMAC key is a demo constant by default
  (override with `ABB_HEAD_KEY`). Someone who holds the key and write access can forge a
  consistent trace; keep the key off the agent's machine.
