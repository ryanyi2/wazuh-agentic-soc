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

## Cost

Measured on the development set (7 cases x 3 runs = 21 analyses), metering
every model call:

| Model | Input tokens per alert | Output tokens per alert | Cost per alert |
|---|---|---|---|
| claude-haiku-4-5 | 2,937 | 397 | $0.0049 |

At that rate, 1,000 alerts a day costs about $4.90 a day. Prompt caching was
considered and not used: Claude Haiku 4.5 only caches prompt prefixes of at
least 4,096 tokens, and an entire request here averages under 3,000 tokens.
The meter reported 0 cached tokens, which confirms it.

## Held-out results

`python evals/run_eval.py evals/holdout.jsonl --repeat 3`: 14 real lab alerts
never used for tuning (6 attacks from three separate brute-force bursts, 8 benign
alerts of types the development set never contained), 42 analyses per run.

The set was run twice. Run 1 exposed a bug in how the eval replays old alerts
(below). Run 2 used the same cases, prompt and context file after that bug was fixed.

| Metric | Run 1: search from now (bug) | Run 2: search anchored at the alert |
|---|---|---|
| Missed threats | 0 of 18 | 0 of 18 |
| Precision when clearing | 1.00 (14 of 14) | 1.00 (19 of 19) |
| Benign alerts cleared | 14 of 24 (0.58) | 19 of 24 (0.79) |
| Triage reduction | 33% (per run 29-43%) | 45% (per run 43-50%) |
| Cost per alert | $0.0050 | $0.0051 |
| Mean latency | 5.1s | 5.5s |

Run 2 is the number to quote. It matches what the live service does, because a
live alert is analysed seconds after it fires.

### The look-ahead bug

The search tool looked back from the current time instead of from when the alert
fired. Replaying a Sep 19 alert on Sep 25 therefore showed the agent brute-force
attacks from Sep 24, which had not happened yet when the alert fired. The fix
anchors the search window at the alert's own timestamp. The anchor comes from the
alert, not from a model argument, so the model cannot move it.

The bug pushed verdicts toward escalation:

| Benign alert | Run 1 cleared | Run 2 cleared |
|---|---|---|
| New service group created (5901) | 1 of 3 | 3 of 3 |
| Package removed (2903) | 1 of 3 | 3 of 3 |
| Rootcheck "trojaned /bin/ls" (510) | 0 of 3 (critical x3) | 1 of 3 |

In run 1 the agent said the rootcheck alert followed "a sustained SSH brute force
attack", an attack that actually came five days later. The two installer alerts
are on the same host, so their searches returned the same later attacks.

The only changes between runs were the fix and the search tool's description,
which now says the window ends when the alert fired. With 3 runs per case, part
of the difference may be run-to-run noise, but every change moved in the
direction the bug predicts.

### What run 2 showed

- Safety held on unseen data: every attack was flagged in every run, and every
  alert the agent cleared was benign.
- The admin-account rule has a cost. A local password typo with no source IP
  (5557) was raised to medium in all 3 runs, because the rule treats a missing
  source as untrusted. The model's own summary called it routine; the code
  overruled it. That is the intended trade: one type of false alarm, in exchange
  for never clearing an attack on the admin account.
- The rootcheck alert is still unstable (high, critical, false_positive). It is
  labelled benign because the flagged binary was checked by hand (it is the
  distribution's own Rust coreutils build). The agent has no tool that can verify
  a binary, so escalating is the defensible answer. The one run that cleared it
  should not be read as good reasoning: it cleared an alert it could not verify.
- The agent's summary exposed a labelling error: the first-time sudo alert came
  from kali-vm, not the manager. The label (benign) was right; the reason was
  corrected.

### Held-out limits

- 14 cases. All six attacks are SSH brute force, the only attack run in the lab.
- Most benign held-out alerts are below the level-9 forwarding threshold, so in
  production they would not reach the agent. A clean lab produces few benign
  level-9+ alerts.
- This set has now been run twice. The second run changed only the replay bug,
  not the prompt, context or labels. Any change made because of these results
  (for example context entries for installer activity, or a file-integrity tool
  for rootcheck alerts) must be measured on a new held-out set.
- The development-set rows above were measured before the fix.
