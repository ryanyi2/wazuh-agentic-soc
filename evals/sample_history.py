"""List past alerts that were never used for tuning, as held-out candidates.

Searches the Wazuh indexer (read-only), skips every alert already in the
development set and the agent's own verdicts, keeps a few examples per rule,
and writes each candidate to a file you can label with add_case.py.

Usage:
    python evals/sample_history.py --since 2026-09-19 --until 2026-09-26
        [--min-level 3] [--per-rule 3] [--out evals/candidates]
"""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path

import httpx

from agentic_soc.config import get_settings


def _dev_ids(path: Path) -> set[str]:
    ids: set[str] = set()
    if path.is_file():
        for line in path.read_text().splitlines():
            if line.strip():
                alert_id = json.loads(line)["alert"].get("id")
                if alert_id:
                    ids.add(alert_id)
    return ids


def main() -> int:
    parser = argparse.ArgumentParser(description="List held-out candidate alerts.")
    parser.add_argument("--since", required=True)
    parser.add_argument("--until", required=True)
    parser.add_argument("--min-level", type=int, default=3)
    parser.add_argument("--per-rule", type=int, default=3)
    parser.add_argument("--out", default="evals/candidates")
    args = parser.parse_args()

    settings = get_settings()
    body = {
        "size": 1000,
        "sort": [{"timestamp": {"order": "asc"}}],
        "query": {
            "bool": {
                "filter": [
                    {"range": {"timestamp": {"gte": args.since, "lt": args.until}}},
                    {"range": {"rule.level": {"gte": args.min_level}}},
                ]
            }
        },
    }
    with httpx.Client(
        base_url=settings.indexer_url,
        auth=(settings.indexer_user, settings.indexer_password),
        verify=settings.indexer_verify_tls,
        timeout=30,
    ) as client:
        response = client.post("/wazuh-alerts-*/_search", json=body)
        response.raise_for_status()
    hits = [hit["_source"] for hit in response.json()["hits"]["hits"]]

    skip = _dev_ids(Path("evals/dataset.jsonl"))
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    per_rule: dict[str, int] = defaultdict(int)
    written = 0
    for alert in hits:
        rule = alert.get("rule", {})
        rule_id = str(rule.get("id"))
        if alert.get("id") in skip or "agentic_soc" in rule.get("groups", []):
            continue
        if per_rule[rule_id] >= args.per_rule:
            continue
        per_rule[rule_id] += 1
        path = out / f"{rule_id}_{per_rule[rule_id]}.json"
        path.write_text(json.dumps(alert, indent=2))
        data = alert.get("data", {})
        source = str(data.get("srcip", "-"))
        user = str(data.get("dstuser") or data.get("srcuser") or "-")
        when = str(alert.get("timestamp", ""))[:19]
        desc = str(rule.get("description", ""))[:55]
        print(f"{path.name:<14} L{rule.get('level'):<3} {when}  {source:<14} {user:<10} {desc}")
        written += 1
    print(f"\n{written} candidates written to {out}/ (skipped {len(skip)} dev-set alerts)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
