# Session Actions

Temporary, repository-related development and test sessions executed on GitHub-hosted runners through the approved Workflow MCP action protocol.

Implementation is tracked by [Spec #1](https://github.com/lirtual/session-actions/issues/1). GitHub workflow discovery is not execution authorization; no session should be dispatched without a published and approved Workflow MCP plan.

## Native Task acceptance

`.github/workflows/verify-action.yml` is a minimal **Task** for validating the approved Workflow MCP lifecycle (not a persistent Session or general-purpose shell). It declares all three required server-owned identity inputs; only the bounded `outcome` choice is caller-selectable.

Before an owner-approved live acceptance, the repository owner must configure these **non-secret Actions variables** with the already-approved Workflow MCP endpoint and audience:

- `WORKFLOW_ACTION_CLAIM_URL` — the HTTPS Worker origin ending in `/github/action/claim`
- `WORKFLOW_ACTION_OIDC_AUDIENCE` — exactly the server's `GITHUB_ACTION_OIDC_AUDIENCE`

The action retries only temporary signed Claim HTTP 503 responses with fresh OIDC tokens, accepts a signed `already_claimed` replay after a lost HTTP receipt, and permanently rejects HTTP 403. It fails closed if either variable, a valid GitHub-issued OIDC token, or the D1 Attempt claim is unavailable. It never reads application secrets or joins Tailscale.

Live `workflow_dispatch` requires the workflow definition on GitHub's **default branch** and an owner-reviewed, SHA-bound Git tag. An approved Task on protected `v0.1.1` actually completed [GitHub Run #40056368526](https://github.com/lirtual/session-actions/actions/runs/40056368526) with signed Claim and successful Workflow MCP terminal reconciliation; CI alone would not prove this.

## Five native Session Actions

Each workflow lives in its own file and uses the same minimal GitHub OIDC → Workflow MCP Claim → private network setup → verified Ready → bounded hold → cleanup sequence:

| Workflow | GitHub-hosted runner | Private access | Local service |
| --- | --- | --- | --- |
| `linux.yml` | Ubuntu | Tailscale SSH | Minimal command-line development |
| `windows.yml` | Windows | SSH public-key as non-admin `sessionuser`; inbound firewall limited to Tailscale interface | PowerShell / files; **no RDP guarantee** |
| `chrome.yml` | Ubuntu | Tailscale SSH forwarding | Chrome DevTools CDP on `127.0.0.1:9222` |
| `code-server.yml` | Ubuntu | Tailscale SSH forwarding | code-server `4.140.0` on `127.0.0.1:8080` |
| `openlist.yml` | Ubuntu | Tailscale SSH forwarding | OpenList Docker `v4.2.6` on `127.0.0.1:5244` |

**How to find your private Session:** the Tailscale Action explicitly assigns `sa-<github_run_id>-a<github_run_attempt>` as the ephemeral node hostname. After the signed Ready state, `workflow_status` exposes `private_hostname` (for example `sa-123456789-a1`) and still reports `physical_health: unverified` until physical state reconciliation. These names work only within an authorized tailnet with correct MagicDNS/Tailscale SSH access rules. For Linux use `ssh runner@sa-<github_run_id>-a<github_run_attempt>`; for Windows use `ssh sessionuser@sa-<github_run_id>-a<github_run_attempt>` with the approved private key. For Chrome, code-server and OpenList use an authenticated SSH local port-forward to the same node on ports 9222, 8080 and 5244 respectively. This is not a public URL or proof of reachability.

**Supply-chain bounds:** the code-server 4.140.0 linux-amd64 download is checked against hardcoded SHA-256 `864c5d01c808ade57e4d12c708717be7a187219fded60428f263b9e2da9f6b48` (matched two distinct GitHub-hosted Runner downloads). OpenList v4.2.6 is pinned to multi-architecture image index digest `sha256:c555c6e1c8af2aead38ed12ec761ac077fdf046d19cf033414be8e056aec6b64`. Any new release must be reviewed and update these immutable values explicitly; the version/tag alone is not authority.

The three internal workflow_dispatch inputs `attempt_id`, `dispatch_id`, `capability_id` are supplied **only** by Workflow MCP. Users may choose `duration_minutes` (1–330, default 330). These workflows do not accept shell commands or arbitrary URLs as input.

**Repository configuration before any separately approved live acceptance:**

- Actions variables: `WORKFLOW_ACTION_CLAIM_URL` (HTTPS, exactly ending `/github/action/claim`), `WORKFLOW_ACTION_OIDC_AUDIENCE` (exact server-owned Action OIDC audience), and `SESSION_SSH_PUBLIC_KEY` (one Ed25519 key, for Windows only).
- Actions variables: `TS_OAUTH_CLIENT_ID` (Tailscale workload identity client ID), `TS_AUDIENCE` (Tailscale OIDC federation audience). These are non-secret identifiers; Tailscale identity binding and tag authorization are enforced by the Tailnet trust policy.
- Actions secret: `OPENLIST_ADMIN_PASSWORD` (OpenList only). Do not paste secret values into Workflow YAML or logs.
- Tailnet: configure a narrowly scoped `tag:session-actions`, an appropriate GitHub workload identity trust policy, ACL grants, and Tailscale SSH rules for the intended identities. The tag does **not** by itself grant SSH or access to other devices.
- Workflow MCP: the signed Claim and Ready endpoints, GitHub Git ref/commit approval, physical Run identity, D1 migrations, four active slots, expiry monitoring and cancellation must be deployed and verified separately.

The signed **Claim runs before** the pinned Tailscale Action, SSH authorization, service secrets and `ready`. An unregistered direct `workflow_dispatch` must stop at Claim; its GitHub Job failure is an expected security result, not proof that the private Session was started. The Tailscale federation needs a client ID, audience, `auth_keys` scope limited to `tag:session-actions`, and an explicit GitHub OIDC trust policy; Tailscale's own [workload identity guide](https://tailscale.com/docs/features/workload-identity-federation) describes the required identity exchange. Do not grant `tag:session-actions` access to unrelated nodes.

Only loopback sockets are used for Chrome, code-server and OpenList. From an authenticated Tailscale SSH connection to the ephemeral node, forward `localhost:9222`, `localhost:8080` or `localhost:5244` respectively. Neither CDP nor code-server has independent HTTP authentication in these fixtures, **so never publish or forward these ports on a public interface**. Restrict Tailscale SSH in tailnet policy.

Windows uses a non-admin temporary user with key-only login and a firewall scoped to the Tailscale adapter. There is no claim of interactive RDP or GUI access until proven in a real Windows-hosted Runner. The OpenList container uses ephemeral Runner-local storage; all Session data is destroyed when the GitHub Job ends. This is intentionally not a storage backup or permanent remote computer.

The GitHub Job has a literal `timeout-minutes: 330` maximum from its actual start. A shared stdlib-only Python helper records an early local timestamp and enforces any shorter user-selected duration. If the Job fails before Ready, the published Workflow must not claim a successful Session. Ready means the private service passed its local health check; it is not a guarantee that the requesting device can connect through Tailnet ACLs.

### Acceptance and publication gate

The five independent Sessions have been exercised through **published and approved** Workflow MCP plans and actual GitHub-hosted runners. Linux [#40057129644](https://github.com/lirtual/session-actions/actions/runs/40057129644) completed signed Claim/Ready, Tailnet SSH command execution, cancellation and quota release. Chrome [#40057287818](https://github.com/lirtual/session-actions/actions/runs/40057287818), code-server [#40057289722](https://github.com/lirtual/session-actions/actions/runs/40057289722) and OpenList [#40057291691](https://github.com/lirtual/session-actions/actions/runs/40057291691) returned signed Ready, supported SSH port-forwarding and actual loopback HTTP responses, then cancelled and released capacity. A four-Session concurrency test denied a fifth attempt without dispatch. Windows [#40060922399](https://github.com/lirtual/session-actions/actions/runs/40060922399) on protected `v0.1.13` passed OIDC Claim, Tailnet and non-admin ED25519 SSH remote command (`WIN_FINAL_PASS`, exit 0), then physically terminated and released its slot. In each case, signed Ready was correctly distinguished from external Job completion.

PR CI checks Actionlint, shared protocol and OIDC Claim failure tests, native Windows prerequisites and actual loopback-bound Chrome, code-server and OpenList service startup. OpenList's local startup now additionally requires a successful admin login with the configured ephemeral password **before** signed Ready; the CI smoke uses only a temporary CI password. A live OpenList Session on protected `v0.1.14` [#40062276499](https://github.com/lirtual/session-actions/actions/runs/40062276499) confirmed the startup script's `OpenList admin login validated` message, signed Ready, authenticated Tailscale SSH access and HTTP 200; normal cancellation reconciled to physical `cancelled`, external `terminated`, and 0 active slots. The five published Session smoke workflows are now pinned to the approved `v0.1.14` SHA. A separate one-minute **natural-expiration** Linux Session [#40062561451](https://github.com/lirtual/session-actions/actions/runs/40062561451) finished its own bounded hold and GitHub Job with `success` (not user cancellation), then the Worker reconciled the external Session to `terminated` / Attempt `succeeded` and restored the active slot count to zero. Broader negative/fault-injection cases are covered in `lirtual/mcp-workers/apps/workflow-mcp-worker/tests/github-action-{oidc,session,orchestration,review,inputs,run-state}.test.ts`, including wrong identities and Git refs, duplicated/lost callbacks, uncertain GitHub responses and no premature quota release. Those are **automated tests**, not live adversarial production experiments. A continuous 330-minute wall-clock run has not been executed; the workflow's 330-minute limit, duration input bounds and short-lived expiration behavior are distinct controls.

Release and acceptance are separate gates. Keep production D1 changes owner-executed, and never bypass the Worker release check for an unresolved or indeterminate Run. Before activating a Session, configure only the approved GitHub/Tailscale workload identity, narrow tag/SSH policy and required private credentials. Do not use a public endpoint as a workaround.
