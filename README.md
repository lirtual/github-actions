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

## Five native Session Actions (Draft)

Each workflow lives in its own file and uses the same minimal GitHub OIDC → Workflow MCP Claim → private network setup → verified Ready → bounded hold → cleanup sequence:

| Workflow | GitHub-hosted runner | Private access | Local service |
| --- | --- | --- | --- |
| `linux.yml` | Ubuntu | Tailscale SSH | Minimal command-line development |
| `windows.yml` | Windows | SSH public-key as non-admin `sessionuser`; inbound firewall limited to Tailscale interface | PowerShell / files; **no RDP guarantee** |
| `chrome.yml` | Ubuntu | Tailscale SSH forwarding | Chrome DevTools CDP on `127.0.0.1:9222` |
| `code-server.yml` | Ubuntu | Tailscale SSH forwarding | code-server `4.140.0` on `127.0.0.1:8080` |
| `openlist.yml` | Ubuntu | Tailscale SSH forwarding | OpenList Docker `v4.2.6` on `127.0.0.1:5244` |

**How to find your private Session:** the Tailscale Action explicitly assigns `sa-<github_run_id>` as the ephemeral node hostname. After the signed Ready state, `workflow_status` exposes `private_hostname` (for example `sa-123456789`) and still reports `physical_health: unverified` until physical state reconciliation. These names work only within an authorized tailnet with correct MagicDNS/Tailscale SSH access rules. For Linux use `ssh runner@sa-<github_run_id>`; for Windows use `ssh sessionuser@sa-<github_run_id>` with the approved private key. For Chrome, code-server and OpenList use an authenticated SSH local port-forward to the same node on ports 9222, 8080 and 5244 respectively. This is not a public URL or proof of reachability.

**Supply-chain bounds:** the code-server 4.140.0 linux-amd64 download is checked against hardcoded SHA-256 `864c5d01c808ade57e4d12c708717be7a187219fded60428f263b9e2da9f6b48` (matched two distinct GitHub-hosted Runner downloads). OpenList v4.2.6 is pinned to multi-architecture image index digest `sha256:c555c6e1c8af2aead38ed12ec761ac077fdf046d19cf033414be8e056aec6b64`. Any new release must be reviewed and update these immutable values explicitly; the version/tag alone is not authority.

The three internal workflow_dispatch inputs `attempt_id`, `dispatch_id`, `capability_id` are supplied **only** by Workflow MCP. Users may choose `duration_minutes` (1–330, default 330). These workflows do not accept shell commands or arbitrary URLs as input.

**Repository configuration before any separately approved live acceptance:**

- Actions variables: `WORKFLOW_ACTION_CLAIM_URL` (HTTPS, exactly ending `/github/action/claim`), `WORKFLOW_ACTION_OIDC_AUDIENCE` (exact server-owned Action OIDC audience), and `SESSION_SSH_PUBLIC_KEY` (one Ed25519 key, for Windows only).
- Actions variables: `TS_OAUTH_CLIENT_ID` (Tailscale workload identity client ID), `TS_AUDIENCE` (Tailscale OIDC federation audience). These are non-secret identifiers; Tailscale identity binding and tag authorization are enforced by the Tailnet trust policy.
- Actions secret: `SESSION_OPENLIST_ADMIN_PASSWORD` (OpenList only). Do not paste secret values into Workflow YAML or logs.
- Tailnet: configure a narrowly scoped `tag:session-actions`, an appropriate GitHub workload identity trust policy, ACL grants, and Tailscale SSH rules for the intended identities. The tag does **not** by itself grant SSH or access to other devices.
- Workflow MCP: the signed Claim and Ready endpoints, GitHub Git ref/commit approval, physical Run identity, D1 migrations, four active slots, expiry monitoring and cancellation must be deployed and verified separately.

Only loopback sockets are used for Chrome, code-server and OpenList. From an authenticated Tailscale SSH connection to the ephemeral node, forward `localhost:9222`, `localhost:8080` or `localhost:5244` respectively. Neither CDP nor code-server has independent HTTP authentication in these fixtures, **so never publish or forward these ports on a public interface**. Restrict Tailscale SSH in tailnet policy.

Windows uses a non-admin temporary user with key-only login and a firewall scoped to the Tailscale adapter. There is no claim of interactive RDP or GUI access until proven in a real Windows-hosted Runner. The OpenList container uses ephemeral Runner-local storage; all Session data is destroyed when the GitHub Job ends. This is intentionally not a storage backup or permanent remote computer.

The GitHub Job has a literal `timeout-minutes: 330` maximum from its actual start. A shared stdlib-only Python helper records an early local timestamp and enforces any shorter user-selected duration. If the Job fails before Ready, the published Workflow must not claim a successful Session. Ready means the private service passed its local health check; it is not a guarantee that the requesting device can connect through Tailnet ACLs.

### Acceptance and publication gate

All five workflows are **Draft code**, not provisioned devices. PR CI checks all YAML with Actionlint, Python syntax and protocol unit tests, Windows PowerShell source parsing, **actual `windows-latest` runner prerequisites**, and secret-free real Ubuntu Runner startup of Chrome, code-server and OpenList on `127.0.0.1`. Signed Ready has a bounded retry for temporary GitHub physical-status inconsistency (`503`) but fails immediately on `403`. These checks do **not** validate Tailnet OIDC grants, real SSH/port-forwarding reachability, Windows SSH account/firewall activation, OpenList login, or a real GitHub `workflow_dispatch` → signed Ready → cancellation lifecycle.

No merge, protected/tag release, production Cloudflare Worker deploy, D1 migration, GitHub secrets, Tailscale trust configuration, actual physical sessions or live E2E should occur without their separate security and release review. Do not set up a public endpoint as a workaround.
