# Agent Firewall: decision-complete MVP plan

Status: approved implementation baseline  
Research snapshot: 2026-08-11  
Target team and window: 2-4 engineers, 8-12 weeks

## 1. Product decision

Agent Firewall is a local-first policy enforcement point for agent actions. It
normalizes tool calls from Codex, Claude Code, OpenClaw, and MCP into one action
schema, evaluates a deterministic policy before execution, requests human
approval when the host supports it, and writes a redacted, hash-chained evidence
record that can be verified and replayed.

The public promise is deliberately narrow:

> One policy and one replayable evidence trail across coding agents and MCP.

It is not an OS sandbox, an endpoint security product, or a claim that every
possible side effect of an arbitrary process can be intercepted.

### Success criteria

- A developer can install one binary, initialize a policy, and protect a first
  Codex or Claude Code action in under five minutes.
- The same policy produces the same decision for semantically equivalent action
  fixtures from Codex, Claude Code, OpenClaw, and MCP.
- A critical action is blocked before execution; a high-risk action uses the
  host's native approval UI where available.
- Audit storage contains no detected secret values, verifies its hash chain,
  and can replay old actions against a new policy.
- The repository ships an attack corpus, reproducible conformance tests,
  checksums, an SBOM, and documented coverage gaps.

### Primary users

1. Individual developers using coding agents on a workstation.
2. Open-source maintainers who want a repository-owned minimum policy.
3. Platform/security teams evaluating agent behavior before a managed rollout.

The first release optimizes for developer trust and GitHub adoption. A future
hosted product may add fleet policy distribution, centralized approval routing,
and independently anchored evidence, but the local engine remains useful with
no account and no network dependency.

## 2. Read-only adjacent-project review

The neighboring `crosscare-agent`, `llm-optimizer-gateway`, and
`procureguard-agent` repositories were inspected read-only. No source, data,
database, artifact, or Git history is shared with this repository.

Practices worth reusing as ideas, not implementation:

- deterministic rules before model judgment;
- explicit simulation and capability boundaries;
- fixed replay/evaluation fixtures;
- redacted append-only audit records;
- release preflight documentation and honest acceptance reports.

Agent Firewall is an independent Go module with its own `.git` directory,
license, dependency graph, fixtures, and release workflow. It does not import
any package from a neighboring project or from `research-grid`.

## 3. Landscape and differentiation

GitHub search on 2026-08-11 shows that the category and generic product name are
crowded. Before a public launch, choose a distinctive brand while retaining
`agent firewall` as the category descriptor.

| Project | Snapshot | Main center of gravity | Gap this MVP targets |
| --- | ---: | --- | --- |
| [Pipelock](https://github.com/luckyPipewrench/pipelock) | 792 stars | mediated network/MCP/A2A traffic and signed receipts | portable host-hook policy and cross-host decision parity |
| [Jig](https://github.com/luyi14-bits/jig) | 168 stars | Python agent framework with an internal ToolGuard | external adapters for existing coding agents |
| [OpenAFW](https://github.com/openafw/openafw) | 98 stars | secret masking and model/API relay | action policy, approval, and replay |
| [Nixis](https://github.com/mayankjain0141/nixis) | 39 stars | Claude-oriented daemon, CEL/IFC, dashboard | daemonless first run and Codex/OpenClaw/MCP parity |
| [Unalome Firewall](https://github.com/unalome-ai/unalome-firewall) | 33 stars | desktop visibility and scanner | policy-as-code and headless enforcement |

The defensible wedge is not another dangerous-command regex list. It is a small,
documented action contract plus conformance fixtures that adapter authors can
implement, and evidence that can be replayed when a policy changes.

## 4. Interception boundaries

### Codex

Use project or user lifecycle hooks:

- `PreToolUse` for `Bash`, unified exec, `apply_patch`, MCP, and other local
  function tools;
- `PostToolUse` to record completion and result metadata;
- `PermissionRequest` only for requests Codex already intends to surface.

Current Codex hooks can deny or rewrite a pre-tool call, but `ask` is not yet a
supported `PreToolUse` result. For `ask`, the MVP fails closed, creates a
one-shot approval request, tells the agent/operator how to approve it, and
allows an identical retry only after approval. Hosted tools and specialized
paths that opt out of hooks are outside this adapter's boundary.

Sources:

- https://learn.chatgpt.com/codex/hooks
- https://learn.chatgpt.com/codex/agent-approvals-security
- https://learn.chatgpt.com/docs/config-file/config-reference

### Claude Code

Use `PreToolUse` and `PostToolUse` command hooks. Claude Code supports native
`allow`, `deny`, and `ask` decisions, so `ask` maps directly to its permission
dialog. Match `Bash|PowerShell` plus file, web, and MCP tools. Project-local hook
configuration is generated as a snippet; the CLI does not silently overwrite an
existing settings file.

Source: https://code.claude.com/docs/en/hooks

### OpenClaw

Ship a small TypeScript plugin adapter using `before_tool_call`. Map decisions to
`block`, no result, or `requireApproval`; record `onResolution` without storing
sensitive parameters. This is the strongest human-approval integration in the
initial set because OpenClaw pauses the run and exposes allow-once,
allow-always, and deny outcomes.

Source: https://docs.openclaw.ai/plugins/hooks

### Generic MCP

Ship a transparent stdio proxy. It forwards newline-delimited JSON-RPC and
intercepts `tools/call` before forwarding it upstream. A denied or pending call
receives a JSON-RPC error with a stable, non-secret reason and approval id. All
other messages pass through unchanged. The first release does not terminate
Streamable HTTP; that is a post-MVP adapter.

Sources:

- https://modelcontextprotocol.io/specification/draft/basic/transports
- https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/authorization

### Coverage rule

Documentation and evidence always name the enforcement point that observed an
action. `observed_by=codex-hook` does not imply OS-wide network or process
coverage. An allowed shell process may create side effects the hook cannot see;
strong containment requires the host sandbox, a container/microVM, or an egress
proxy in addition to Agent Firewall.

## 5. Architecture

```text
Codex hook ---------+
Claude hook --------+     +------------------+     +------------------+
OpenClaw plugin ----+---->| action normalizer |--->| policy evaluator |
MCP stdio proxy ----+     +------------------+     +---------+--------+
JSON CLI/API -------+                                      |
                                                   allow / ask / deny
                                                            |
                              +-----------------------------+----------------+
                              |                                              |
                     host-native approval                         one-shot grant store
                              |                                              |
                              +-----------------------------+----------------+
                                                            |
                                                  redacted evidence ledger
                                                            |
                                                 verify / export / replay
```

### Go package boundaries

```text
cmd/agent-firewall/       thin CLI entry point
internal/action/          canonical action and risk/signal types
internal/analyze/         shell, path, URL, tool, and secret-reference analysis
internal/policy/          YAML loading, validation, matching, decision traces
internal/approval/        expiring one-shot grants bound to an action fingerprint
internal/audit/           redaction, append-only JSONL hash chain, verify/replay
internal/adapter/         Codex and Claude hook codecs
internal/mcpproxy/        transparent stdio JSON-RPC proxy
integrations/openclaw/    TypeScript plugin adapter
testdata/                 host fixtures and adversarial action corpus
```

### Technology decisions

- Go: a small cross-platform static binary, fast startup for synchronous hooks,
  straightforward concurrency, and simple release artifacts.
- YAML policy: readable and diffable. The schema is intentionally smaller than
  Rego/CEL for the first release; a CEL expression escape hatch is deferred until
  the canonical action schema stabilizes.
- JSONL instead of SQLite: append semantics, inspectability, portable export,
  and zero database migration burden. Hosted ingestion can consume the same
  event schema later.
- SHA-256 chain: detects truncation/reordering/modification when a trusted head
  hash is retained. It is not non-repudiation against an attacker who can rewrite
  the entire ledger; external anchors are post-MVP.
- No model-based policy decision in the enforcement path. Optional semantic
  review can be advisory later, but deterministic rules own allow/deny.

## 6. Public interfaces

The binary name is `agent-firewall`; examples may use the shorter shell alias
`afw` only when the user creates it.

```text
agent-firewall init [--policy PATH]
agent-firewall check [--policy PATH] [--input PATH|-]
agent-firewall hook --host codex|claude [--policy PATH]
agent-firewall mcp proxy [--policy PATH] -- COMMAND [ARG...]
agent-firewall approvals list|approve|deny [ID]
agent-firewall audit list|verify|export|replay
agent-firewall policy validate [PATH]
agent-firewall doctor
agent-firewall version
```

All machine-facing commands emit JSON on stdout and diagnostics on stderr.
Exit codes are stable:

- `0`: successful operation or allow decision;
- `2`: policy deny;
- `3`: approval required;
- `4`: invalid input or policy;
- `5`: internal or storage failure.

### Canonical action (`afw.action/v1alpha1`)

```json
{
  "schema": "afw.action/v1alpha1",
  "id": "optional host call id",
  "timestamp": "2026-08-11T12:00:00Z",
  "source": "codex",
  "session_id": "redacted or hashed host session id",
  "workspace": "/work/repo",
  "kind": "shell",
  "operation": "curl",
  "subject": "https://api.example.com/v1",
  "attributes": {
    "command": "curl ...",
    "tool_name": "Bash",
    "arguments": {}
  },
  "signals": ["network", "secret-reference"],
  "risk": "high"
}
```

Kinds in v1alpha1 are `shell`, `file_read`, `file_write`, `network`, `secret`,
and `tool`. Adapters preserve the original tool name and arguments while the
normalizer extracts paths, hosts, executables, and security signals.

### Decision (`afw.decision/v1alpha1`)

```json
{
  "schema": "afw.decision/v1alpha1",
  "decision": "ask",
  "risk": "high",
  "rule_id": "network-with-secret-reference",
  "reason": "Network action references a sensitive credential source",
  "action_fingerprint": "sha256:...",
  "approval_id": "apr_...",
  "policy_digest": "sha256:...",
  "trace": [{"rule_id":"...","matched":true,"priority":90}]
}
```

Decision values are `allow`, `ask`, and `deny`. Reasons are safe for display and
must never interpolate matched secret values.

## 7. Policy format

Policy schema: `afw.policy/v1alpha1`.

```yaml
version: afw.policy/v1alpha1
name: balanced-local

defaults:
  low: allow
  medium: ask
  high: ask
  critical: deny
  on_error: deny

redaction:
  environment:
    - '*_TOKEN'
    - '*_SECRET'
    - '*_PASSWORD'
  paths:
    - '**/.env*'
    - '**/.ssh/**'
    - '**/.aws/credentials'

rules:
  - id: deny-destructive-root
    description: Never permit destructive root or device operations
    priority: 1000
    decision: deny
    match:
      kinds: [shell]
      signals: [destructive-root]

  - id: ask-network-write
    description: Review outbound state-changing network requests
    priority: 100
    decision: ask
    match:
      signals: [network-write]

  - id: allow-workspace-writes
    description: Permit ordinary writes inside the active workspace
    priority: 50
    decision: allow
    match:
      kinds: [file_write]
      path_scope: workspace
      exclude_path_globs: ['**/.env*', '**/.git/hooks/**']
```

Matching fields in v1alpha1:

- `sources`, `kinds`, `operations`, `tool_globs`, `path_globs`,
  `exclude_path_globs`, `host_globs`, `signals`, `risk_at_least`;
- `path_scope`: `workspace`, `outside-workspace`, or `any`;
- `command_regex` and `argument_regex` using Go RE2 syntax.

Evaluation is deterministic:

1. Validate and normalize the action.
2. Collect all matching rules.
3. Select only matches at the highest priority.
4. Within that priority, use `deny > ask > allow`.
5. If no rule matches, use the risk-level default.
6. Bind an existing one-shot approval only when action fingerprint, workspace,
   policy digest, expiry, and remaining-use count all match.

Unknown fields are rejected. Invalid regex, invalid enum values, duplicate rule
ids, or an unreadable policy fail closed.

## 8. MVP and non-goals

### MVP

- canonical action and decision schemas;
- deterministic YAML policy with explain traces;
- shell/file/network/tool normalization and conservative risk signals;
- Codex and Claude command-hook adapters;
- OpenClaw plugin adapter;
- MCP stdio `tools/call` proxy;
- native approval mapping when available and expiring one-shot grants otherwise;
- redacted hash-chained JSONL evidence, verify, export, and replay;
- doctor/init/validate commands;
- golden host fixtures, adversarial corpus, fuzz targets, and CI/release files.

### Explicit non-goals

- OS-wide process, filesystem, or network containment;
- TLS interception, transparent system proxying, or packet inspection;
- arbitrary script semantic analysis or proof that an allowed process is safe;
- Streamable HTTP MCP termination in v0.1;
- Windows PowerShell AST analysis beyond host-provided structured fields;
- LLM-based allow/deny decisions;
- organization identity, SSO, RBAC, fleet rollout, or cloud approval routing;
- tamper-proof logs against a fully privileged local attacker;
- automatic editing of pre-existing user-level Codex/Claude/OpenClaw config;
- a desktop dashboard.

## 9. Test matrix

| Layer | Required cases |
| --- | --- |
| Policy | schema rejection, duplicate ids, bad regex, priority, deny precedence, defaults, deterministic digest |
| Shell | compound commands, pipes, redirects, command substitution, encoded URLs, sudo, destructive root, reverse shell, package install, git force push |
| Files | relative/absolute normalization, `..`, symlinks as unresolved risk, outside workspace, `.env`, SSH/AWS paths, `.git/hooks` |
| Network | HTTP methods, curl/wget aliases, localhost/private IP/metadata IP, URL credentials, shell egress after secret reference |
| Secrets | common token formats and sensitive references; prove evidence contains category/count only, never value |
| Adapters | golden Codex and Claude Pre/Post inputs, malformed JSON, missing fields, ask mapping, failure mapping |
| OpenClaw | allow/block/requireApproval mapping and safe `onResolution` record |
| MCP | pass-through lifecycle, concurrent ids, notification pass-through, tools/call allow/ask/deny, child exit, oversized line |
| Approval | fingerprint binding, expiry, single use, policy change, workspace change, concurrent consume |
| Audit | append concurrency, verify clean chain, detect edit/reorder/truncate with retained head, redaction, replay drift |
| Platforms | macOS/Linux/Windows unit tests; stdio integration on macOS/Linux; race detector on Linux |
| Robustness | Go fuzzing for action JSON, policy YAML, shell input, and MCP frames; `govulncheck`; dependency license check |

Release gates:

- `go test ./...` and `go test -race ./...` pass;
- adversarial corpus has 100% block/ask recall for declared critical/high cases;
- no detected secret literal appears in ledger fixtures;
- MCP pass-through fixtures remain byte-equivalent when no decision is needed;
- fresh install smoke tests pass from release archives on macOS and Linux;
- threat model and coverage certificate match the shipped adapters.

## 10. Delivery plan

| Week | Deliverable |
| --- | --- |
| 1 | action schema, policy schema, CLI skeleton, initial threat model |
| 2 | evaluator, shell/file/network analyzers, golden unit fixtures |
| 3 | Codex and Claude adapters plus init snippets |
| 4 | approval store, audit ledger, verify/export/replay |
| 5 | MCP stdio proxy and fake-server integration suite |
| 6 | OpenClaw plugin, host conformance suite, doctor command |
| 7 | adversarial corpus, fuzzing, race/security checks, performance budget |
| 8 | docs site content, demo recording, GoReleaser, SBOM/checksum release candidate |
| 9-10 | beta feedback, host-version compatibility fixes, policy examples |
| 11-12 | optional signing/anchoring spike, v0.1 launch, post-launch triage |

With two engineers, weeks 9-12 are hardening only. With four, one pair can own
host adapters and another can own engine/evidence while one person rotates onto
docs, attack fixtures, and release engineering.

## 11. Release and GitHub-star plan

### Packaging

- Apache-2.0 license, Code of Conduct, contribution guide, security policy;
- GitHub release archives for macOS/Linux/Windows amd64/arm64;
- checksums, CycloneDX SBOM, GitHub artifact attestations, and pinned build action
  revisions;
- `go install` path for contributors; Homebrew tap after the first stable tag;
- no curl-pipe-shell installer in v0.1.

### Launch assets

- 90-second terminal demo: malicious instruction -> policy explanation -> native
  approval/block -> audit verify -> replay after policy change;
- comparison page centered on enforcement boundaries rather than feature counts;
- public `agent-action-corpus` fixtures and adapter conformance badge;
- four copy-paste quickstarts: Codex, Claude Code, OpenClaw, generic MCP;
- "what we cannot intercept" page linked from the README hero section.

### Hosted option retained

The local schemas become the hosted ingestion contract. Paid/hosted features can
later include policy bundles, signed bundle rollout, organization approval
queues, evidence retention, external timestamp/transparency anchoring,
coverage/drift reports, and SIEM export. Local evaluation and single-user audit
stay open and offline.

## 12. Decisions intentionally deferred

- Distinct public brand and domain: required before launch because "Agent
  Firewall" is crowded.
- CEL/Rego: reconsider after v1alpha1 action fixtures stabilize.
- Streamable HTTP MCP proxy: v0.2 candidate after the 2026-07-28 ecosystem
  migration is observed.
- Signed evidence: first define key custody and recovery; a local signature whose
  key sits beside the log adds little security.
- GUI/daemon: add only if approval latency and discoverability data justify the
  operational complexity.
