"""Print sha256 hashes of the detection logic: policy file and the modules that implement rules.

Used to write docs/FREEZE.json at the moment the policy is frozen for the holdout, and by
tests/test_freeze.py to show whether detection logic changed afterwards.
"""

import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FROZEN_FILES = [
    "policies/default.yaml",
    "src/agentblackbox/policy.py",
    "src/agentblackbox/normalize.py",
    "src/agentblackbox/secrets.py",
    "src/agentblackbox/taint.py",
    "src/agentblackbox/canary.py",
    "src/agentblackbox/guard.py",
]


def hashes() -> dict[str, str]:
    return {f: hashlib.sha256((ROOT / f).read_bytes()).hexdigest() for f in FROZEN_FILES}


if __name__ == "__main__":
    json.dump(hashes(), sys.stdout, indent=2, sort_keys=True)
    print()
