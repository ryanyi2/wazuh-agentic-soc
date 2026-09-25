# Evaluation results

Each row is `python evals/run_eval.py --repeat 3` over `evals/dataset.jsonl`.
Model: claude-haiku-4-5. Current Claude models accept no temperature setting,
so every case runs 3 times and the per-run spread is reported.

| Change | Prompt | Context | Cases | Benign cleared | Triage reduction (per-run range) | Missed threats |
|---|---|---|---|---|---|---|
| Baseline | v1 | none | 5 | 3 of 9 | 20% (0-40%) | 0 |
| Severity rubric | v2 | none | 5 | 4 of 9 | 27% (0-40%) | 0 |
| Control for context | v3 | none | 5 | 5 of 9 | 33% (20-40%) | 0 |
| Environment context | v3 | infrastructure.yaml | 5 | 9 of 9 | 60% (60-60%) | 0 |
| + admin-account floor | v3 | infrastructure.yaml | 7 | 9 of 9 | 43% (43-43%) | 0 |

Triage reduction can never exceed the benign share of the dataset:
60% for the 5-case set (3 benign), 43% for the 7-case set (3 benign).

## Reading

- v1 to v2 to v3 without context: each step moved one verdict out of fifteen,
  inside the run-to-run spread. Prompt wording alone did not measurably help.
- With the prompt and cases held fixed, adding environment context (who the
  admin is, which networks are trusted) cleared every benign alert in every run
  and removed the run-to-run variation, with no missed threats.

## Adversarial test: attacks on the admin account

Telling the model who the admin is creates an obvious risk, because an attacker
chooses the username. Probe: failed logins to `ryanyi` from an untrusted host
(192.168.64.2), labelled true_positive, run as a held-out case with context loaded.

- Before the fix: verdicts false_positive, medium, high. Cleared in 1 of 3 runs,
  so a missed threat. The model reasoned that a "known administrator" failing
  from a "local network IP" was legitimate.
- Fix: a code-enforced policy (admin-auth-failure-from-untrusted-source, minimum
  medium), and a missing source IP now counts as untrusted.
- After the fix: both admin-account cases (the 5760 and the level-10 2502 from the
  same incident) were never cleared in 3 runs. The policy fired on 2502, where
  the model's own summary claimed the source was "their own workstation", a fact
  that appears nowhere in the context.
- Because the fix was made after seeing this case, it is no longer held out. It
  now lives in the development set as a regression test.

## Limits

- Seven cases. The three benign ones are all the same kind of event (the admin
  mistyping a password on the manager).
- The context file was written by someone who knew these cases. Its facts are
  true, but this set cannot show how well they generalise.
- These are development-set numbers. Numbers to quote come from a fresh
  held-out set that is never tuned on.
- Triage reduction depends on the benign/malicious mix of the dataset. A real
  SOC queue is mostly benign, so this percentage is not a production estimate.
