# Triage Eval

- Run at: 2026-10-28T16:14:47.260563+00:00
- Model: `gemini-3.8-flash`
- Command: `uv run python -m evals.run_eval --delay 1 --retries 1`
- Cases: 20 (18 labeled, 2 unknown)
- Data snapshot: 5300 indicators (300 malicious, 5000 benign)

## Metrics

| Metric | Value |
|---|---:|
| Labeled accuracy | 72.2% (13/18) |
| Escalation rate | 65.0% (13/20) |
| Required escalations met | 2/2 |
| Unknown cases escalated | 2/2 |
| Confidently wrong | 0 |
| False negatives | 0 |
| False positives | 0 |
| Pipeline errors | 0 |
| Average latency | 23833 ms |

Accuracy is computed only on the malicious/benign labeled cases. Unknown cases are synthetic escalation checks and are excluded from accuracy.

### By case group

| Group | Correct | Labeled | Accuracy | Escalated |
|---|---:|---:|---:|---:|
| benign | 7 | 8 | 87.5% | 1/8 |
| seen_malicious | 6 | 6 | 100.0% | 6/6 |
| unknown | 0 | 0 | n/a | 2/2 |
| unseen_malicious | 0 | 4 | 0.0% | 4/4 |

## Per-case results

| ID | Group | Input | Expected | Predicted | Severity | Confidence | Status | Correct | Tools |
|---|---|---|---|---|---|---:|---|---|---|
| seen-mal-01 | seen_malicious | `https://019-7lfcn-lh1-vxbva7-ou0bwr.pages.dev/` | malicious | malicious | high | 0.85 | needs_review | yes | lookup_indicator=ok, enrich_domain=partial, extract_url_features=ok |
| seen-mal-02 | seen_malicious | `https://678coin.top/` | malicious | malicious | critical | 0.95 | needs_review | yes | lookup_indicator=ok, enrich_domain=ok, extract_url_features=ok |
| seen-mal-03 | seen_malicious | `https://87uxj.com/` | malicious | malicious | high | 0.92 | needs_review | yes | lookup_indicator=ok, enrich_domain=ok, extract_url_features=ok |
| seen-mal-04 | seen_malicious | `http://alibabaglobalnetwork.com/` | malicious | malicious | high | 0.85 | needs_review | yes | lookup_indicator=ok, enrich_domain=ok, extract_url_features=ok |
| seen-mal-05 | seen_malicious | `https://capgemini.m365-microsoft.com/home/daaa8a144d524f76be39aebd5124498e` | malicious | malicious | critical | 0.95 | needs_review | yes | lookup_indicator=ok, enrich_domain=partial, extract_url_features=ok |
| seen-mal-06 | seen_malicious | `https://auth.properties/E.aUtDFan446dX?/microsoftonline/mailbox/upgrade` | malicious | malicious | critical | 0.95 | needs_review | yes | lookup_indicator=ok, enrich_domain=ok, extract_url_features=ok |
| unseen-mal-01 | unseen_malicious | `https://000-054343-info.weebly.com/login` | malicious | unknown | medium | 0.65 | needs_review | no | lookup_indicator=not_found, enrich_domain=partial, extract_url_features=ok |
| unseen-mal-02 | unseen_malicious | `https://0000000000000190000010111.weebly.com/` | malicious | unknown | low | 0.60 | needs_review | no | lookup_indicator=not_found, enrich_domain=partial, extract_url_features=ok |
| unseen-mal-03 | unseen_malicious | `https://0002985647.weebly.com/verify` | malicious | unknown | medium | 0.60 | needs_review | no | lookup_indicator=not_found, enrich_domain=partial, extract_url_features=ok |
| unseen-mal-04 | unseen_malicious | `https://001zimbra.weebly.com/` | malicious | unknown | medium | 0.60 | needs_review | no | lookup_indicator=not_found, enrich_domain=partial, extract_url_features=ok |
| ben-01 | benign | `https://nyt.com/` | benign | benign | info | 0.85 | auto_closed | yes | lookup_indicator=not_found, enrich_domain=ok, extract_url_features=ok |
| ben-02 | benign | `https://procyclingstats.com/` | benign | benign | info | 0.80 | auto_closed | yes | lookup_indicator=not_found, enrich_domain=ok, extract_url_features=ok |
| ben-03 | benign | `https://klook.com/login` | benign | benign | info | 0.85 | auto_closed | yes | lookup_indicator=not_found, enrich_domain=ok, extract_url_features=ok |
| ben-04 | benign | `https://europepmc.org/` | benign | benign | info | 0.85 | auto_closed | yes | lookup_indicator=not_found, enrich_domain=ok, extract_url_features=ok |
| ben-05 | benign | `https://computrabajo.com/login` | benign | benign | info | 0.85 | auto_closed | yes | lookup_indicator=not_found, enrich_domain=ok, extract_url_features=ok |
| ben-06 | benign | `https://pinterest.co.uk/` | benign | benign | info | 0.85 | auto_closed | yes | lookup_indicator=not_found, enrich_domain=ok, extract_url_features=ok |
| ben-07 | benign | `https://thespruce.com/` | benign | benign | info | 0.85 | auto_closed | yes | lookup_indicator=not_found, enrich_domain=ok, extract_url_features=ok |
| ben-08 | benign | `https://domru.ru/` | benign | unknown | info | 0.65 | needs_review | no | lookup_indicator=not_found, enrich_domain=partial, extract_url_features=ok |
| unk-01 | unknown | `https://nonexistent-a1b2c3d4.invalid/` | unknown | unknown | info | 0.50 | needs_review | n/a | lookup_indicator=not_found, enrich_domain=partial, extract_url_features=ok |
| unk-02 | unknown | `https://missing-e5f6g7h8.invalid/login` | unknown | unknown | low | 0.50 | needs_review | n/a | lookup_indicator=not_found, enrich_domain=partial, extract_url_features=ok |

## Confidently wrong

None in this run.

## Escalated cases

- `seen-mal-01` (malicious -> malicious, confidence 0.85): enrich_domain returned degraded status: partial; malicious verdicts require human review before blocking action; high or critical severity requires human review
- `seen-mal-02` (malicious -> malicious, confidence 0.95): malicious verdicts require human review before blocking action; high or critical severity requires human review
- `seen-mal-03` (malicious -> malicious, confidence 0.92): malicious verdicts require human review before blocking action; high or critical severity requires human review
- `seen-mal-04` (malicious -> malicious, confidence 0.85): malicious verdicts require human review before blocking action; high or critical severity requires human review
- `seen-mal-05` (malicious -> malicious, confidence 0.95): enrich_domain returned degraded status: partial; malicious verdicts require human review before blocking action; high or critical severity requires human review
- `seen-mal-06` (malicious -> malicious, confidence 0.95): malicious verdicts require human review before blocking action; high or critical severity requires human review
- `unseen-mal-01` (malicious -> unknown, confidence 0.65): enrich_domain returned degraded status: partial; confidence 0.65 is below the 0.7 threshold; classification is unknown
- `unseen-mal-02` (malicious -> unknown, confidence 0.60): enrich_domain returned degraded status: partial; confidence 0.60 is below the 0.7 threshold; classification is unknown
- `unseen-mal-03` (malicious -> unknown, confidence 0.60): enrich_domain returned degraded status: partial; confidence 0.60 is below the 0.7 threshold; classification is unknown
- `unseen-mal-04` (malicious -> unknown, confidence 0.60): enrich_domain returned degraded status: partial; confidence 0.60 is below the 0.7 threshold; classification is unknown
- `ben-08` (benign -> unknown, confidence 0.65): enrich_domain returned degraded status: partial; confidence 0.65 is below the 0.7 threshold; classification is unknown
- `unk-01` (unknown -> unknown, confidence 0.50): enrich_domain returned degraded status: partial; confidence 0.50 is below the 0.7 threshold; classification is unknown
- `unk-02` (unknown -> unknown, confidence 0.50): enrich_domain returned degraded status: partial; confidence 0.50 is below the 0.7 threshold; classification is unknown

## Limitations

- The eval set has 20 cases and is intentionally small; these numbers are not a
  production estimate.
- Malicious labels come from OpenPhish (seen cases) and the Phishing Army active
  blocklist (unseen cases); both can be noisy or stale. Benign labels come from Tranco
  ranks and are not verified non-malicious.
- Six malicious cases are already loaded in BigQuery and test the lookup happy path;
  four malicious cases are held out and test generalization. The benign cases are
  outside the loaded top 5000. The feeds are not independent ground truth.
- Gemini calls are nondeterministic. This is a single run, not a repeated sample.
- One formatter call hit a transient 429 during this run; the harness retried it
  successfully. Only final pipeline errors are counted in the metrics.
- RDAP gaps and shared-hosting subdomains frequently produce partial enrichment; the
  policy deliberately escalates those cases.
- The policy auto-closes only confident benign verdicts. Malicious, high/critical,
  unknown, degraded, conflicting, or low-confidence results are escalated.
- Pipeline errors are counted as fail-closed `needs_review` results with unknown
  classification.
