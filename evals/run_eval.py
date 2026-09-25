"""Run the agent over a labelled dataset and print an evaluation report.

Usage: python evals/run_eval.py [path/to/dataset.jsonl]
"""

from __future__ import annotations

import sys
from pathlib import Path

from agentic_soc.agent.anthropic_client import AnthropicLLM
from agentic_soc.agent.loop import run_agent
from agentic_soc.agent.wazuh_tools import make_search_alerts_tool
from agentic_soc.clients.indexer import IndexerClient
from agentic_soc.config import get_settings
from agentic_soc.evaluation import evaluate, load_cases
from agentic_soc.models import Alert, Verdict


def main() -> int:
    dataset = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("evals/dataset.jsonl")
    cases = load_cases(dataset)
    settings = get_settings()
    llm = AnthropicLLM(settings.anthropic_api_key, settings.model, settings.max_tokens)

    tools = {}
    if settings.indexer_url:
        indexer = IndexerClient(
            settings.indexer_url,
            settings.indexer_user,
            settings.indexer_password,
            settings.indexer_verify_tls,
        )
        tools = {"search_alerts": make_search_alerts_tool(indexer)}

    def run(alert: Alert) -> Verdict:
        return run_agent(alert, llm, tools)

    report = evaluate(cases, run)
    print(f"cases:                 {report.total}")
    print(f"triage reduction:      {report.triage_reduction:.0%}")
    print(f"suppression precision: {report.suppression_precision:.2f}")
    print(f"missed true positives: {report.missed_threats}")
    print(f"caught threats:        {report.caught_threats}")
    print(f"mean latency:          {report.mean_latency_seconds:.1f}s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
