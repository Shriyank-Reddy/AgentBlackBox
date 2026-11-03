# Policy reference

A policy is one YAML file. It is validated when loaded; an error names the rule and the
field (`rule 'net.egress.allowlist': field 'deny_if.domain_not_in' must be a list of
non-empty strings`). Examples: [`policies/default.yaml`](../policies/default.yaml) and
[`policies/strict.yaml`](../policies/strict.yaml).

## Top-level fields

| Field | Type | Default | Meaning |
|---|---|---|---|
| `version` | `1` | required | Schema version. |
| `mode` | `enforce` \| `monitor` | `enforce` | `enforce`: a deny raises `PolicyViolation` and the tool does not run. `monitor`: nothing is blocked; the trace records what *would* have been denied (`blocked: false`). |
| `default` | `deny` \| `allow` | `deny` | With `deny`, any tool not listed under `tools` is denied with rule id `policy.unknown_tool`. |
| `tools` | list of names | required if `default: deny` | The tool allow-list. |
| `sandbox_root` | absolute path | `/sandbox` | Virtual root that relative paths resolve against. |
| `outbound_tools` | list of names | `http_get, http_post, send_email, shell` | Tools that can move data out. Canary detection applies to these. |
| `taint` | mapping | empty | Where taint labels come from (below). |
| `rules` | list | empty | The rules (below). |

## `taint`

```yaml
taint:
  private_paths:   ["workspace/private/", "/home/agent/.ssh/"]  # reading here => private_data
  untrusted_paths: ["workspace/inbox/"]                          # reading here => untrusted_content
  private_tools:   [get_env]                                     # results are private_data
  untrusted_tools: [http_get]                                    # results are untrusted_content
  min_fragment: 16   # chars; a call inherits a label if its arguments contain a fragment this long
```

Labels: `private_data`, `untrusted_content`. Short private values (6 to `min_fragment`-1
characters, e.g. a password from `get_env`) are matched whole.

## Rules

```yaml
rules:
  - id: net.egress.allowlist        # unique, required
    description: ...                # optional
    tools: [http_get, http_post]    # names; fnmatch wildcards such as "*" are allowed
    deny_if: { arg: url, domain_not_in: [api.github.com, "*.readthedocs.io"] }
    severity: high                  # low | medium | high | critical (default medium)
```

Exactly one of `deny_if` (blocks) or `flag_if` (allowed but marked `flag` for review).

### Conditions

| Condition | Meaning |
|---|---|
| `{arg: A, not_under: [P...]}` / `{arg: A, under: [P...]}` | Argument `A`, normalised as a path (traversal, `~`, encoded separators resolved), is outside / inside the prefixes. Relative prefixes are relative to `sandbox_root`. Compared by whole path components, so `workspace2` is not under `workspace/`. |
| `{arg: A, domain_not_in: [H...]}` / `domain_in` | Host of URL argument `A`, after normalisation. Entries match exactly; `*.example.com` matches subdomains but not the apex. URLs with userinfo (`@`), backslashes, IP literals, bad schemes, encoded hosts or control characters never match an allow-list. |
| `{arg: A, urls_not_in: [H...]}` | Every URL found inside the string `A` (for example a shell command) must have a listed host. |
| `{arg: A, email_domain_not_in: [D...]}` | Every address in `A` (comma/semicolon separated, `Name <addr>` allowed) must be on a listed domain. |
| `{arg: A, matches: REGEX}` | Python regex found in argument `A`. |
| `{arg: A, shell_dangerous: true}` | The shell string in `A` contains a destructive, obfuscated or remote-code-execution pattern (see `analyze_shell`). |
| `{any_arg_contains: secret}` | Any argument, in raw, URL-, base64-, hex-decoded, NFKC or zero-width-stripped form, contains a secret pattern or a redaction marker. |
| `{any_arg_contains: [w...]}` | Any argument contains one of the words (case-insensitive). |
| `{session_has_all: [L...]}` / `{session_has_any: [L...]}` | The session (plus this call's arguments) carries all / any of the labels. |
| `{call_has_taint: [L...]}` | This call's arguments contain a fragment of a value with one of the labels. |
| `{same_call_repeated: N}` | The identical call (same tool, same arguments) has now been attempted N times. |
| `{session_call_count_over: N}` | More than N calls in the session. |
| `{all_of: [...]}`, `{any_of: [...]}`, `{not: {...}}` | Combinators. |

A condition about an argument that is missing or not a string simply does not match.

## Evaluation order

1. **Canary** (built in, cannot be disabled): a canary token, in any encoding, in the arguments
   of an `outbound_tools` call is denied with `canary.exfil`.
2. **Unknown tool** (when `default: deny`): `policy.unknown_tool`.
3. **Rules**, in file order. Every matching rule is reported; any `deny_if` match makes the
   decision `deny`, otherwise any `flag_if` match makes it `flag`, otherwise `allow`.

In `monitor` mode the decision is recorded but never enforced.

## Example: tightening a policy and replaying

```bash
abb replay examples/demo_trace.jsonl --policy policies/strict.yaml
```

See the real output in the README and in [`docs/results/replay_demo_strict.txt`](results/replay_demo_strict.txt).
