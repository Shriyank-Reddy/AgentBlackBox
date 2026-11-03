"""Transparency check for the dev/holdout split.

docs/FREEZE.json holds the hashes of the detection logic at the commit "freeze policy for
holdout". If this test fails, rules or normalisation changed AFTER the holdout was written.
That is allowed, but the README must say so plainly (see "Rule changes after the freeze").
Update docs/FREEZE.json only together with that README note.
"""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from freeze_hashes import hashes  # noqa: E402


def test_detection_logic_matches_freeze_record():
    frozen = json.loads((ROOT / "docs" / "FREEZE.json").read_text())
    changed = sorted(f for f, h in hashes().items() if frozen.get(f) != h)
    assert not changed, f"detection logic changed since the holdout freeze: {changed}"
