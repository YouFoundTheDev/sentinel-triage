# Triage Eval

- Run at: 2026-10-28T19:02:15.737369+00:00
- Agent model: `gemini-3.8-flash`
- Command: `uv run python -m evals.run_eval --mode both --case-ids seen-mal-01,seen-mal-02,seen-mal-03,seen-mal-04,unseen-mal-01,unseen-mal-02,unseen-mal-03,unseen-mal-04,ben-01,ben-03,unk-01,unk-02 --delay 20 --retries 2`
- Cases: 12 (10 labeled, 2 unknown)
- Data snapshot: 5300 indicators (300 malicious, 5000 benign)
- BQML model: `wide-factor-387115.triage.url_classifier` over 5291 feature rows; accuracy 0.998, roc_auc 1.000

This Stage 6 comparison uses a quota-limited subset of 12/20 cases because the full ML run hit Vertex AI 429/timeouts. The full 20-case no-ML Stage 3 baseline was 72.2% accuracy (13/18) and 65% escalation.

> **Bottom line:** this is a small, single-run portfolio eval. The no-ML baseline is stronger than the ML subset run; BQML holdout metrics are not agent metrics.

## Methodology

- Cases: 6 seen malicious (OpenPhish, loaded), 4 unseen malicious (Phishing Army), 8 benign
  (Tranco ranks outside the loaded top 5,000), and 2 synthetic unknown `.invalid` hosts. The
  full set has 20 cases; the Stage 6 comparison uses 12.
- Accuracy counts only malicious/benign labeled cases. Unknown cases test required
  escalation and are excluded from accuracy.
- `needs_review` is the escalation rate. A confidently wrong case is a labeled case whose
  predicted classification is wrong with confidence ≥ 0.7.
- The six seen malicious domains are excluded from BQML training. The BQML metrics come
  from a random 20% split of the remaining indicator feature table, not from these agent
  cases.

Reproduce: `make ml && make eval`.

## Comparison

| Metric | Without ML | With ML |
|---|---:|---:|
| Labeled accuracy | 60.0% | 30.0% |
| Escalation rate | 83.3% | 91.7% |
| Required escalations met | 2 | 2 |
| Unknown cases escalated | 2 | 2 |
| Confidently wrong | 0 | 0 |
| False negatives | 0 | 0 |
| False positives | 0 | 0 |
| Pipeline errors | 0 | 0 |
| Average latency | 43458 ms | 29547 ms |

Accuracy is computed only on malicious/benign labeled cases. Unknown cases are synthetic escalation checks and are excluded from accuracy.

The ML tool did not improve this subset. It disagreed with lookup on two seen malicious cases, and it scored a benign login URL as malicious; the formatter and policy responded by escalating to unknown/needs_review. The high BQML holdout metrics (shown above) do not translate to agent decisions, likely because the lexical features separate feed sources rather than generalize to real-world URL intent.

### By case group

| Group | Baseline accuracy | ML accuracy | Baseline escalated | ML escalated |
|---|---:|---:|---:|---:|
| benign | 100.0% | 50.0% | 0/2 | 1/2 |
| seen_malicious | 100.0% | 50.0% | 4/4 | 4/4 |
| unknown | n/a | n/a | 2/2 | 2/2 |
| unseen_malicious | 0.0% | 0.0% | 4/4 | 4/4 |

## Per-case results

| ID | Group | Input | Expected | Baseline | Baseline status | ML | ML status |
|---|---|---|---|---|---|---|---|
| seen-mal-01 | seen_malicious | `https://019-7lfcn-lh1-vxbva7-ou0bwr.pages.dev/` | malicious | malicious / high / 0.85 | needs_review | malicious / critical / 0.95 | needs_review |
| seen-mal-02 | seen_malicious | `https://678coin.top/` | malicious | malicious / critical / 0.95 | needs_review | unknown / medium / 0.65 | needs_review |
| seen-mal-03 | seen_malicious | `https://87uxj.com/` | malicious | malicious / high / 0.88 | needs_review | unknown / medium / 0.65 | needs_review |
| seen-mal-04 | seen_malicious | `http://alibabaglobalnetwork.com/` | malicious | malicious / high / 0.85 | needs_review | malicious / critical / 0.95 | needs_review |
| unseen-mal-01 | unseen_malicious | `https://000-054343-info.weebly.com/login` | malicious | unknown / medium / 0.60 | needs_review | unknown / medium / 0.65 | needs_review |
| unseen-mal-02 | unseen_malicious | `https://0000000000000190000010111.weebly.com/` | malicious | unknown / low / 0.55 | needs_review | unknown / medium / 0.65 | needs_review |
| unseen-mal-03 | unseen_malicious | `https://0002985647.weebly.com/verify` | malicious | unknown / medium / 0.65 | needs_review | unknown / medium / 0.65 | needs_review |
| unseen-mal-04 | unseen_malicious | `https://001zimbra.weebly.com/` | malicious | unknown / medium / 0.60 | needs_review | unknown / medium / 0.65 | needs_review |
| ben-01 | benign | `https://nyt.com/` | benign | benign / info / 0.85 | auto_closed | benign / info / 0.85 | auto_closed |
| ben-03 | benign | `https://klook.com/login` | benign | benign / info / 0.85 | auto_closed | unknown / medium / 0.65 | needs_review |
| unk-01 | unknown | `https://nonexistent-a1b2c3d4.invalid/` | unknown | unknown / info / 0.50 | needs_review | unknown / medium / 0.50 | needs_review |
| unk-02 | unknown | `https://missing-e5f6g7h8.invalid/login` | unknown | unknown / low / 0.50 | needs_review | unknown / medium / 0.50 | needs_review |

## Confidently wrong

### Without ML

None in this run.

### With ML

None in this run.

## ML impact

- `seen-mal-02`: malicious/needs_review -> unknown/needs_review (ML predicts benign but lookup found only malicious sightings)
- `seen-mal-03`: malicious/needs_review -> unknown/needs_review (ML predicts benign but lookup found only malicious sightings)
- `ben-03`: benign/auto_closed -> unknown/needs_review (model classification/status changed; no ML-specific policy reason)

## Limitations

- The eval set has 20 cases and is intentionally small; these numbers are not a
  production estimate.
- Malicious labels come from OpenPhish (seen cases) and the Phishing Army active
  blocklist (unseen cases); both can be noisy or stale. Benign labels come from Tranco
  ranks and are not verified non-malicious.
- Nine malicious holdout domains (including the six seen cases and three unseen cases)
  were excluded from BQML training; the remaining unseen cases and benign cases are outside
  the loaded indicators. This reduces, but does not eliminate, evaluation leakage and
  distribution shift.
- This Stage 6 comparison is a 12-case quota-limited subset. The full 20-case ML run hit
  Vertex AI 429/timeouts; rerun `make eval` with quota available for the full comparison.
- BQML metrics come from a random 20% split of the indicator feature table, not from
  the 20 agent eval cases. Both numbers are small-sample and single-run.
- Gemini and ML are probabilistic. This is one run, not a repeated sample.
- RDAP gaps and shared-hosting subdomains frequently produce partial enrichment; the
  policy deliberately escalates those cases.
- The policy auto-closes only confident benign verdicts. Malicious, high/critical,
  unknown, degraded, conflicting, or low-confidence results are escalated.
- Pipeline errors are counted as fail-closed `needs_review` results with unknown
  classification.
