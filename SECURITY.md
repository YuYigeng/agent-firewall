# Security policy

## Supported versions

Agent Firewall is pre-release. Only the latest tagged version will receive
security fixes until a stable support policy is published.

## Reporting a vulnerability

Do not open a public issue for a plausible bypass, secret leak, approval replay,
or evidence-integrity flaw. Use GitHub's private vulnerability reporting for the
repository.

Include:

- Agent Firewall version/commit and OS;
- host and host version;
- adapter and policy digest;
- a minimal action using fake credentials only;
- expected and actual decision;
- whether the action reached execution;
- logs with secrets and personal paths removed.

We aim to acknowledge a report within three business days, provide an initial
assessment within seven days, and coordinate disclosure after a fix is
available. These are goals, not a paid support SLA.

## Scope notes

The documented coverage gaps in [`docs/THREAT_MODEL.md`](./docs/THREAT_MODEL.md)
are not vulnerabilities by themselves. A supported hook/proxy action that is
forwarded contrary to its evaluated deny, a fail-open parser path, approval
grant reuse, or a stored detected secret is in scope.
