## Summary

<!-- What changed and why? -->

## Verification

- [ ] `make lint`
- [ ] `make test`
- [ ] `docs/eval.md` updated only from a real eval run (if behavior changed)
- [ ] `README.md` / `infra/README.md` updated for command, IAM, or endpoint changes

## Security checklist

- [ ] No secrets, credentials, tokens, or `.env` files committed
- [ ] No code path fetches the submitted URL
- [ ] BigQuery remains parameterized
- [ ] Fail-closed escalation rules still hold
- [ ] IAM changes remain least-privilege

## Notes for reviewers

<!-- Rollout, cost, or follow-up notes. -->
