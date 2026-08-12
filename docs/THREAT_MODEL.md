# Threat model

Version: v0.1 baseline  
Last reviewed: 2026-08-11

## Security objective

Agent Firewall reduces the chance that an agent action visible at a supported
hook or proxy boundary performs an unauthorized destructive, exfiltrating,
privilege-changing, persistent, or high-impact operation. It makes the policy
decision explainable and leaves redacted evidence for later verification and
replay.

It is one layer in a defense-in-depth design. It does not convert same-user hooks
into a kernel security boundary.

## Assets

- source code, uncommitted work, and repository history;
- credentials, environment variables, SSH material, cloud configuration, and
  local browser/session data;
- external systems reachable through MCP tools or network calls;
- the correctness and availability of the developer workstation;
- policy files, approval grants, and audit evidence;
- user attention and the meaning of an approval prompt.

## Adversaries and failure sources

1. Indirect prompt injection in a repository, web result, issue, document, or
   tool response.
2. A compromised or malicious MCP server/tool description.
3. An agent reasoning error or hallucinated destructive command.
4. A malicious dependency, install script, or generated shell fragment.
5. Approval fatigue or a misleading action description.
6. A repository contributor who can change project-local policy/hook files.
7. Parser ambiguity, adapter drift, fail-open errors, and audit corruption.

A fully privileged local attacker who can modify the binary, active hook
configuration, policy, grant store, ledger, and retained head hash is outside the
MVP integrity claim. Managed deployments must put these artifacts outside the
agent-writable boundary.

## Trust boundaries

```text
untrusted prompt/model/tool output
              |
              v
      host tool-call object     (host contract; version-sensitive)
              |
              v
       adapter/normalizer       (trusted code, untrusted input)
              |
              v
        policy evaluator        (trusted policy only)
         /      |       \
      allow    ask      deny
        |       |         |
        |   human/host    +---- no execution at observed boundary
        |       |
        +-------+-----> host or upstream MCP execution
                            |
                            v
                  post-event evidence (best effort)
```

Project-local policies are not automatically trusted when an untrusted
repository can edit them. A production deployment should use an explicit
user/managed policy path that the agent sandbox cannot write, and treat
repository policy as a narrowing layer only.

## Threats and controls

| Threat | MVP control | Residual risk |
| --- | --- | --- |
| destructive shell | parse/extract shell operations; critical signals deny | aliases, interpreters, generated scripts, and allowed binaries can hide behavior |
| sensitive file write | normalize paths; workspace scope; sensitive globs; ask/deny | TOCTOU and symlink changes require OS controls |
| credential access/exfiltration | detect sensitive references and network combination; redact evidence | secret may be transformed, read inside an allowed process, or sent through an unobserved channel |
| risky MCP tool | stdio proxy and host hooks inspect `tools/call` name/arguments | direct server access, Streamable HTTP, and opaque tool behavior remain |
| approval replay | grant binds action fingerprint, workspace, policy digest, expiry, one use | semantically equivalent but differently encoded actions require a new approval |
| prompt injection changes policy | policy path is explicit; digest recorded; managed placement recommended | same-user process can still edit an unprotected policy |
| audit leaks secrets | structured redaction before append; do not interpolate secret values in reasons | unknown secret formats or high-entropy non-secrets may evade/misfire |
| audit tampering | previous-hash chain and retained head check | full local rewrite is possible without external anchor |
| parser/adapter failure | strict schema, bounded input, valid fail-closed host response, error evidence | if hook binary is absent/disabled, the host may run without this layer |
| hook coverage gap | explicit adapter coverage certificate and doctor checks | hosted/specialized tools and child-process side effects are not intercepted |
| malicious tool result | post-event redaction/recording; future taint signals | side effect already happened before PostToolUse |
| denial of service | bounded frame size/timeouts; local-only storage | fail-closed policy can interrupt development when storage is unavailable |

## High-risk chains

The analyzer should flag combinations more strongly than isolated indicators:

- sensitive file or environment reference + outbound network;
- decoded/obfuscated content + shell execution;
- downloaded content + chmod/execute;
- write to shell/profile, Git hooks, agent config, or package lifecycle file;
- credential tool + external message/upload tool;
- force push/reset/clean against a protected branch or broad workspace;
- private/metadata endpoint access from an untrusted tool flow.

MVP chain detection is within one visible action. Cross-action taint tracking is
post-MVP because host session semantics and false-positive costs need dedicated
evaluation.

## Fail-closed behavior

- Invalid policy, action, regex, storage state, or internal evaluation returns a
  valid host-specific deny response whenever the adapter process is running.
- An MCP proxy never forwards a `tools/call` it could not parse or evaluate.
- Approval expiry, policy digest change, workspace change, or concurrent grant
  consumption means no grant.
- Audit append failure denies `ask`/`deny` decisions and, in strict mode, denies
  all actions. The default MVP mode is strict.
- Human-approval timeout is deny; there is no timeout-to-allow setting.

## Evidence claims

Each decision event records the action fingerprint, redacted normalized action,
policy digest, selected rule, decision, risk, observer, timestamps, and previous
event hash. Completion events may add duration, success/error category, and a
digest of already-redacted result metadata.

The ledger proves internal consistency relative to a retained trusted head. It
does not prove that:

- every system action passed through Agent Firewall;
- the underlying host input accurately described future side effects;
- the user, agent, or same-user malware could not replace the entire ledger;
- an allowed action was safe.

## Required security tests

- golden block/ask cases for every threat row above;
- fuzz malformed action JSON, YAML, shell text, path inputs, and MCP frames;
- race test grant consumption and concurrent ledger append;
- seed a known fake secret and assert it never appears in decision output,
  stderr, ledger, export, or replay output;
- mutate, reorder, remove, and truncate evidence records and verify detection
  when a trusted head is supplied;
- disable or corrupt each adapter dependency and verify doctor/deny behavior;
- test versioned fixtures from each supported host release before publishing a
  compatibility claim.

## Disclosure boundary

Security reports should include the host, host version, adapter, policy digest,
minimal redacted action, expected decision, actual decision, and whether the
action executed. Never attach real credentials or unredacted transcripts.
