"""Append a labelled case to an eval dataset from a captured alert JSON file.

Usage:
    python evals/add_case.py <alert.json> <true_positive|false_positive> "<reason>"
        [--dataset evals/holdout.jsonl]
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description="Append a labelled case to an eval dataset.")
    parser.add_argument("alert", help="path to a captured alert JSON file")
    parser.add_argument("label", choices=["true_positive", "false_positive"])
    parser.add_argument("reason", help="why this label is correct")
    parser.add_argument("--dataset", default="evals/dataset.jsonl")
    args = parser.parse_args()

    alert = json.loads(Path(args.alert).read_text())
    row = {"alert": alert, "label": args.label, "reason": args.reason}
    dataset = Path(args.dataset)
    with dataset.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(row) + "\n")
    print(f"added {args.label} case -> {dataset}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
