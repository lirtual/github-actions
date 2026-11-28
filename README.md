# GitHub Actions

Personal GitHub-hosted Tasks and temporary Sessions for Workflow MCP.

Runtime behavior is defined by the workflows and tests. Production execution and authorization are managed separately.

Ubuntu and Windows Sessions use the immutable Release Agent by default. The
explicit `session_agent=rust-candidate` choice is for authorized acceptance,
builds the platform-specific Rust Candidate from a reviewed commit pin, and
starts it as the sole Session Agent. Candidate mode requires its exact GitHub
Action contract to be approved in the published Workflow before it can run.

The immutable Latest metadata lookup uses the job-scoped read-only GitHub
token; the token is not passed to the downloaded Agent or asset download.

Signed Ready confirms private SSH (and Windows RDP), not RCA connectivity.
If the optional RCA bootstrap fails, the Session remains available over SSH/RDP;
inspect the bootstrap step's `phase` and safe `reason` code (including HTTP
status/rate limit and Release validation failures). It does not print raw
exceptions, URLs, response bodies or credentials.
