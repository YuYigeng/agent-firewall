# Contributing

Agent Firewall welcomes focused issues and pull requests. Security-boundary
changes need stronger evidence than ordinary feature changes.

## Development

```bash
go test ./...
go test -race ./...
go vet ./...
```

Before a pull request:

1. Add or update a public corpus case for every new allow/ask/deny behavior.
2. Add a host golden fixture when an adapter wire shape changes.
3. State whether the change expands, narrows, or does not affect execution
   coverage.
4. Prove fake secret values do not reach stdout, stderr, evidence, or replay.
5. Update the threat model when a trust boundary or fail mode changes.

Do not commit real transcripts, credentials, user home paths, generated runtime
data, or copied code/data from neighboring projects. New dependencies require a
maintenance, license, and supply-chain rationale.

Use private vulnerability reporting rather than a public issue for suspected
security bypasses.
