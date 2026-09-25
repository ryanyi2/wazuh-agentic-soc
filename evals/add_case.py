"""Append a labelled case to the eval dataset from a captured alert JSON file.

Usage:
    python evals/add_case.py <alert.json> <true_positive|false_positive> "<reason>"
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

VALID = {"true_positive", "false_positive"}


def main() -> int:
    if len(sys.argv) != 4 or sys.argv[2] not in VALID:
        print(__doc__)
        return 1
    alert_path, label, reason = sys.argv[1], sys.argv[2], sys.argv[3]
    alert = json.loads(Path(alert_path).read_text())
    row = {"alert": alert, "label": label, "reason": reason}
    dataset = Path("evals/dataset.jsonl")
    with dataset.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(row) + "\n")
    print(f"added {label} case -> {dataset}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
