# Session Actions

Temporary, repository-related development and test sessions executed on GitHub-hosted runners through the approved Workflow MCP action protocol.

Implementation is tracked by [Spec #1](https://github.com/lirtual/session-actions/issues/1). GitHub workflow discovery is not execution authorization; no session should be dispatched without a published and approved Workflow MCP plan.

## Native Task acceptance

`.github/workflows/verify-action.yml` is a minimal **Task** for validating the approved Workflow MCP lifecycle (not a persistent Session or general-purpose shell). It declares all three required server-owned identity inputs; only the bounded `outcome` choice is caller-selectable.

Before an owner-approved live acceptance, the repository owner must configure these **non-secret Actions variables** with the already-approved Workflow MCP endpoint and audience:

- `WORKFLOW_ACTION_CLAIM_URL` — the HTTPS Worker origin ending in `/github/action/claim`
- `WORKFLOW_ACTION_OIDC_AUDIENCE` — exactly the server's `GITHUB_ACTION_OIDC_AUDIENCE`

The action deliberately fails closed if either variable, a valid GitHub-issued OIDC token, or the D1 Attempt claim is unavailable. It never reads application secrets or joins Tailscale.

Live `workflow_dispatch` requires the workflow definition on GitHub's **default branch** and an owner-reviewed, SHA-bound Git tag. A Draft PR and passing source tests do **not** satisfy that release requirement. Do not merge, create production credentials, or deploy as part of this acceptance fixture.
