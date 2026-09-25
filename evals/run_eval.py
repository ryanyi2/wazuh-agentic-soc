"""Run the agent over a labelled dataset and print per-case and summary results.

Usage:
    python evals/run_eval.py [dataset.jsonl] [--repeat N] [--no-context]

Runs the same pipeline as the live service (environment facts -> agent ->
policy floors). LLM output can vary between runs, so --repeat runs every case
N times and reports pooled metrics plus the per-run spread. --no-context runs
without the environment context file, for a with/without comparison.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from agentic_soc.agent.anthropic_client import AnthropicLLM
from agentic_soc.agent.loop import analyze_alert
from agentic_soc.agent.prompt import PROMPT_VERSION
from agentic_soc.agent.wazuh_tools import make_search_alerts_tool
from agentic_soc.clients.indexer import IndexerClient
from agentic_soc.config import get_settings
from agentic_soc.context import EnvironmentContext, load_context
from agentic_soc.evaluation import CaseResult, load_cases, run_cases, summarize
from agentic_soc.models import Alert, Verdict


def _outcome(result: CaseResult) -> str:
    if result.missed_threat:
        return "MISSED THREAT"
    if result.is_benign and not result.suppressed:
        return "noisy"
    return "ok"


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate the agent on a labelled dataset.")
    parser.add_argument("dataset", nargs="?", default="evals/dataset.jsonl")
    parser.add_argument("--repeat", type=int, default=1, help="run every case N times")
    parser.add_argument(
        "--no-context", action="store_true", help="run without the environment context file"
    )
    args = parser.parse_args()

    cases = load_cases(Path(args.dataset))
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

    context: EnvironmentContext | None = None
    context_path = Path(settings.context_path)
    if not args.no_context and context_path.is_file():
        context = load_context(context_path)

    def run(alert: Alert) -> Verdict:
        return analyze_alert(alert, llm, tools, context)

    context_label = str(context_path) if context is not None else "none"
    print(
        f"prompt {PROMPT_VERSION} | model {settings.model} | context {context_label} | "
        f"{len(cases)} cases x {args.repeat} runs\n"
    )
    runs = [run_cases(cases, run) for _ in range(args.repeat)]

    for i, case in enumerate(cases):
        results = [run_results[i] for run_results in runs]
        suppressed = sum(1 for r in results if r.suppressed)
        outcomes = ", ".join(sorted({_outcome(r) for r in results}))
        verdicts = ", ".join(r.verdict.risk_level.value for r in results)
        policies = sorted({p for r in results for p in r.verdict.applied_policies})
        print(
            f"{case.label.value:<15} rule {case.alert.rule.id:<5} "
            f"suppressed {suppressed}/{args.repeat}  [{outcomes}]"
        )
        print(f"    verdicts: {verdicts}")
        if policies:
            print(f"    policies: {', '.join(policies)}")
        print(f"    e.g.: {results[0].verdict.summary}")

    pooled = summarize([r for run_results in runs for r in run_results])
    per_run = [summarize(run_results).triage_reduction for run_results in runs]
    print()
    print(
        f"triage reduction:      {pooled.triage_reduction:.0%}  "
        f"(per run {min(per_run):.0%}-{max(per_run):.0%})"
    )
    print(f"suppressed:            {pooled.suppressed} of {pooled.total}")
    print(
        f"benign cleared:        {pooled.correct_suppressions} of {pooled.benign_total}  "
        f"(recall {pooled.suppression_recall:.2f})"
    )
    print(f"suppression precision: {pooled.suppression_precision:.2f}")
    print(f"missed true positives: {pooled.missed_threats}")
    print(f"caught threats:        {pooled.caught_threats}")
    print(f"mean latency:          {pooled.mean_latency_seconds:.1f}s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
