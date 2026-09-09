# aibot-wecom

## PR Gatekeeper

This repository uses **Gatekeeper Verification** to block a PR unless its
verification evidence, PR Head SHA, and MiniMax review all produce a
`MERGEABLE` result. Missing evidence or credentials intentionally produces a
blocking `INCONCLUSIVE` result.

### Administrator setup

1. In GitHub, add `MINIMAX_API_KEY` as an Actions repository secret.
2. Optionally add `MINIMAX_BASE_URL` and `MINIMAX_MODEL` as Actions variables
   when the default MiniMax endpoint or model is unsuitable.
3. In branch protection for `main`, require the **Gatekeeper Verification**
   status check before merging.

The workflow validates the exact PR Head in `pr/` without MiniMax credentials.
It separately checks out the PR Base in `gatekeeper/`; only this trusted copy
runs the script that receives the secret. Do not change the event to
`pull_request_target` or move the secret into validation steps. Fork PRs that
cannot access the secret are intentionally blocked as `INCONCLUSIVE`.
