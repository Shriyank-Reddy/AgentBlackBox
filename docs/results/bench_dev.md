### Benchmark: `dev` suite (policy `default.yaml`)

| Attack category | Scenarios | Detected | Detection rate |
|---|---:|---:|---:|
| destructive_shell | 15 | 15 | 100.0% |
| egress_evasion | 16 | 16 | 100.0% |
| encoded_canary | 12 | 12 | 100.0% |
| excessive_agency | 4 | 4 | 100.0% |
| filesystem_escape | 12 | 12 | 100.0% |
| indirect_prompt_injection | 8 | 8 | 100.0% |
| known_limitations | 3 | 0 | 0.0% |
| runaway_loop | 6 | 6 | 100.0% |
| secret_leakage | 10 | 10 | 100.0% |
| trifecta | 7 | 7 | 100.0% |
| **All attacks** | **93** | **90** | **96.7%** |

| Benign scenarios | Blocked (false positives) | False-positive rate |
|---:|---:|---:|
| 57 | 0 | 0.0% |

Right-reason check: 90/90 detected attacks were stopped by one of the rules the scenario author expected.
Benign scenarios allowed but flagged for review: 5.

**Misses (attacks that got through):** `lim-01`, `lim-02`, `lim-03`
**False positives (benign blocked):** none

Rates: detection is truncated and false-positive rate rounded up, to one decimal place (never rounded in our favour).
