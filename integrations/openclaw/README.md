# OpenClaw adapter

This native plugin evaluates every `before_tool_call` with the local
`agent-firewall` binary. `ask` maps to OpenClaw's native `requireApproval` flow;
deny and evaluation failures block the tool before execution.

The plugin requires OpenClaw 2026.7.28 or later and an installed
`agent-firewall` binary. Configure absolute paths so a Gateway working-directory
change cannot select a different policy:

```json
{
  "plugins": {
    "entries": {
      "agent-firewall": {
        "enabled": true,
        "config": {
          "binary": "/usr/local/bin/agent-firewall",
          "policy": "/absolute/path/agent-firewall.yaml",
          "workspace": "/absolute/path/to/workspace",
          "dataDir": "/absolute/path/to/firewall-data",
          "timeoutMs": 5000
        }
      }
    }
  }
}
```

Install or link this directory, then inspect it before enabling:

```bash
openclaw plugins install ./integrations/openclaw --link
openclaw plugins inspect agent-firewall --runtime --json
openclaw plugins enable agent-firewall
openclaw plugins doctor
```

The adapter is a policy hook, not an OS sandbox. Any process allowed by the hook
can still create child-process side effects that OpenClaw does not expose as
separate tool calls.
