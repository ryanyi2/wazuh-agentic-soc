"""Run the agent over a labelled dataset and print per-case and summary results.

Usage: python evals/run_eval.py [path/to/dataset.jsonl]
"""

from __future__ import annotations

import sys
from pathlib import Path

from agentic_soc.agent.anthropic_client import AnthropicLLM
from agentic_soc.agent.loop import run_agent
from agentic_soc.agent.prompt import PROMPT_VERSION
from agentic_soc.agent.wazuh_tools import make_search_alerts_tool
from agentic_soc.clients.indexer import IndexerClient
from agentic_soc.config import get_settings
from agentic_soc.evaluation import CaseResult, load_cases, run_cases, summarize
from agentic_soc.models import Alert, Verdict


def _outcome(result: CaseResult) -> str:
    if result.missed_threat:
        return "MISSED THREAT"
    if result.is_benign and not result.suppressed:
        return "noisy: benign escalated"
    return "ok"


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

    print(f"prompt {PROMPT_VERSION} | model {settings.model} | {len(cases)} cases\n")
    results = run_cases(cases, run)
    for r in results:
        v = r.verdict
        print(
            f"{r.case.label.value:<15} rule {r.case.alert.rule.id:<5} -> "
            f"{v.risk_level.value:<15} conf={v.confidence:.2f}  [{_outcome(r)}]"
        )
        print(f"    {v.summary}")

    report = summarize(results)
    print()
    print(f"triage reduction:      {report.triage_reduction:.0%}")
    print(f"suppressed:            {report.suppressed} of {report.total}")
    print(f"suppression precision: {report.suppression_precision:.2f}")
    print(f"missed true positives: {report.missed_threats}")
    print(f"caught threats:        {report.caught_threats}")
    print(f"mean latency:          {report.mean_latency_seconds:.1f}s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
