# Acceptance status

Snapshot: 2026-08-11  
Version: `0.1.0-dev`

This report separates implemented and locally verified behavior from host-level
integration work that still requires the corresponding product runtime.

| Capability | Status | Evidence |
| --- | --- | --- |
| canonical action and decision | verified locally | unit tests and public action corpus |
| YAML policy validation/priority | verified locally | schema, bad-regex, duplicate/unknown-field, precedence tests |
| shell/file/network/tool analysis | verified locally | analyzer tests and 21-case adversarial corpus across three sources |
| Codex hook codec | wire fixture + CLI smoke verified | valid deny, ask-via-one-shot, approved retry outputs |
| Claude hook codec | wire fixture + CLI smoke verified | native `ask` and critical `deny` outputs |
| OpenClaw plugin | source-complete, runtime pending | official API shape implemented; no local OpenClaw runtime available in this workspace |
| MCP stdio proxy | verified locally | fake upstream integration proves pending tool is not forwarded |
| one-shot approval | verified locally | binding, deduplication, wrong-workspace rejection, single consumption |
| redacted hash-chain ledger | verified locally | fake-secret exclusion and tamper-detection tests |
| audit replay | verified locally | four decision events replayed with zero policy drift; human overrides normalize back to `ask` |
| release artifacts | configured, not published | pinned CI actions and GoReleaser configuration |

## Manual smoke evidence

Using an isolated data directory inside this repository:

- Codex-format `rm -rf /` returned `permissionDecision: deny` before execution.
- Claude-format `npm install left-pad` returned `permissionDecision: ask`.
- Codex-format package install returned a one-shot approval id; after approval,
  one identical retry returned `allow`.
- `audit verify` reported a valid four-event chain after those actions.
- Replaying those four decision events against the same policy reported zero
  drift, including the explicitly approved action.
- `go test ./...`, `go test -race ./...`, `go vet ./...`, formatting checks,
  and `govulncheck ./...` passed. Seed fuzz targets cover shell normalization,
  strict policy parsing, and MCP frame decoding; bounded local fuzz runs passed
  for all three targets.

No actual destructive command or package installation was executed during the
smoke test; only hook JSON was evaluated.

## Remaining release blockers

1. Install into current Codex CLI/desktop and Claude Code releases and capture
   true pre/post host events.
2. Run `openclaw plugins validate`, `inspect --runtime`, and an approval flow on
   OpenClaw 2026.7.28 or newer.
3. Expand host-version golden fixtures and run Windows PowerShell host testing.
4. Run clean archive smoke tests and release artifact attestation in GitHub
   Actions on the public repository.
5. Select a distinctive public brand; "Agent Firewall" has significant naming
   collision in the current GitHub landscape.

Until those blockers are closed, the repository should be described as a
working security-focused MVP, not production-certified endpoint enforcement.
