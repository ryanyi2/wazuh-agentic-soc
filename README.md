# Agentic SOC Analyst for Wazuh

An LLM-driven alert-triage service for the [Wazuh](https://wazuh.com) SIEM. It
intercepts high-severity alerts, investigates each one with read-only tools, and
writes a structured verdict back into Wazuh as a native alert.

## The problem

A security operations center generates thousands of alerts a day, and most are
noise. Analysts burn out sorting them and miss the one that mattered — this is
"alert fatigue," the defining operational problem in a SOC. This service acts as
a tireless tier-1 analyst that triages every high-severity alert and explains its
reasoning.

## What makes it *agentic*

A typical AI integration shows an alert to a model and prints the reply. This
service gives the model tools and lets it **investigate before deciding**:

- Search the alert history for related events on the same host or source IP
- Look up facts about the affected agent (OS, last activity, prior findings)
- Check indicators (IPs, file hashes) against threat-intelligence sources
- Compare against a written baseline of what is normal in this environment

It returns a structured verdict — risk level, reasoning, probable cause, MITRE
ATT&CK technique, and the commands a human should run next.

## Architecture (in progress)

    Wazuh (rule fires) -> integration hook -> ingest API -> bounded agent loop
                                                              |  read-only tools
                                                              v
                                                  verdict -> back into Wazuh

Key design constraints, documented as the code lands:

- **Fire-and-forget ingestion.** Wazuh's integration subsystem times out in ~10s;
  the agent takes longer. The hook hands the alert off and exits immediately;
  all analysis is asynchronous.
- **Read-only.** The agent can look at anything and change nothing. The worst
  outcome of a wrong verdict is a bad opinion — never a blocked user or a deleted
  account.
- **Policy in code, judgment in the model.** Deterministic rules ("a successful
  login from outside the network always escalates") are enforced before the model
  runs, not left to its discretion.

## Status

Active development, built in phases against a live Wazuh + Kali lab.

- [x] Real alert corpus captured from the lab
- [ ] Alert data model
- [ ] Ingestion path (integration hook + API)
- [ ] Read-only tool clients (indexer, server API, threat intel)
- [ ] Bounded agent loop (tool-call, latency, and cost ceilings)
- [ ] Environment context + deterministic overrides
- [ ] Verdict writeback into Wazuh
- [ ] Evaluation harness (precision/recall on false-positive suppression)

## Tech

Python - FastAPI - Pydantic - Wazuh - OpenSearch - Anthropic API - MITRE ATT&CK

## License

MIT - see [LICENSE](LICENSE).
