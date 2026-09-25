"""Print the most recent Wazuh alerts for labelling (rule id, level, description).

Run with sudo so it can read the alert log:
    sudo python3 evals/show_recent.py [count]
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ALERTS = Path("/var/ossec/logs/alerts/alerts.json")


def main() -> int:
    count = int(sys.argv[1]) if len(sys.argv) > 1 else 10
    for line in ALERTS.read_text(encoding="utf-8").splitlines()[-count:]:
        try:
            alert = json.loads(line)
        except ValueError:
            continue
        rule = alert.get("rule", {})
        rid = str(rule.get("id", "?"))
        level = str(rule.get("level", "?"))
        desc = str(rule.get("description", ""))[:70]
        print(f"{rid:>6} | L{level:>2} | {desc}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
