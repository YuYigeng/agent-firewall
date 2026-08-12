package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/YuYigeng/agent-firewall/internal/action"
	"github.com/YuYigeng/agent-firewall/internal/adapter"
	"github.com/YuYigeng/agent-firewall/internal/analyze"
	"github.com/YuYigeng/agent-firewall/internal/approval"
	"github.com/YuYigeng/agent-firewall/internal/audit"
	"github.com/YuYigeng/agent-firewall/internal/engine"
	"github.com/YuYigeng/agent-firewall/internal/mcpproxy"
	"github.com/YuYigeng/agent-firewall/internal/policy"
)

const Version = "0.1.0-dev"

const (
	ExitOK       = 0
	ExitDenied   = 2
	ExitApproval = 3
	ExitInvalid  = 4
	ExitInternal = 5
)

type App struct {
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
}

func (a *App) Run(ctx context.Context, args []string) int {
	if a.Stdin == nil {
		a.Stdin = os.Stdin
	}
	if a.Stdout == nil {
		a.Stdout = os.Stdout
	}
	if a.Stderr == nil {
		a.Stderr = os.Stderr
	}
	if len(args) == 0 {
		a.usage()
		return ExitInvalid
	}
	var code int
	var err error
	switch args[0] {
	case "init":
		code, err = a.runInit(args[1:])
	case "check":
		code, err = a.runCheck(ctx, args[1:])
	case "hook":
		code, err = a.runHook(ctx, args[1:])
	case "policy":
		code, err = a.runPolicy(args[1:])
	case "approvals":
		code, err = a.runApprovals(ctx, args[1:])
	case "audit":
		code, err = a.runAudit(args[1:])
	case "mcp":
		code, err = a.runMCP(ctx, args[1:])
	case "doctor":
		code, err = a.runDoctor(args[1:])
	case "version", "--version", "-v":
		fmt.Fprintf(a.Stdout, "agent-firewall %s\n", Version)
		return ExitOK
	case "help", "--help", "-h":
		a.usage()
		return ExitOK
	default:
		err = fmt.Errorf("unknown command %q", args[0])
		code = ExitInvalid
	}
	if err != nil {
		fmt.Fprintf(a.Stderr, "agent-firewall: %v\n", err)
	}
	return code
}

func (a *App) runInit(args []string) (int, error) {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(a.Stderr)
	policyPath := fs.String("policy", "agent-firewall.yaml", "policy path to create")
	if err := fs.Parse(args); err != nil {
		return ExitInvalid, err
	}
	absPolicy, err := filepath.Abs(*policyPath)
	if err != nil {
		return ExitInvalid, err
	}
	if err := policy.WriteDefault(absPolicy); err != nil {
		if os.IsExist(err) {
			return ExitInvalid, fmt.Errorf("policy already exists: %s", absPolicy)
		}
		return ExitInternal, err
	}
	command := fmt.Sprintf("agent-firewall hook --host HOST --policy %s", shellQuote(absPolicy))
	result := map[string]any{
		"created": absPolicy,
		"next_steps": []string{
			"Review the policy before enabling hooks.",
			"Merge one generated hook snippet into the host configuration; existing files were not modified.",
			"Run agent-firewall doctor --policy " + absPolicy,
		},
		"codex_hooks":  hookSnippet(strings.Replace(command, "HOST", "codex", 1)),
		"claude_hooks": hookSnippet(strings.Replace(command, "HOST", "claude", 1)),
	}
	return ExitOK, writeJSON(a.Stdout, result)
}

func (a *App) runCheck(ctx context.Context, args []string) (int, error) {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	fs.SetOutput(a.Stderr)
	policyPath, dataDir := commonFlags(fs)
	inputPath := fs.String("input", "-", "canonical action JSON path or - for stdin")
	native := fs.Bool("native-approval", false, "the calling host can surface an approval")
	observer := fs.String("observer", "json-cli", "evidence observer id")
	if err := fs.Parse(args); err != nil {
		return ExitInvalid, err
	}
	eng, err := loadEngine(*policyPath, *dataDir)
	if err != nil {
		return ExitInvalid, err
	}
	reader := a.Stdin
	var file *os.File
	if *inputPath != "-" {
		file, err = os.Open(*inputPath)
		if err != nil {
			return ExitInvalid, err
		}
		defer file.Close()
		reader = file
	}
	raw, err := io.ReadAll(io.LimitReader(reader, 8*1024*1024+1))
	if err != nil {
		return ExitInvalid, fmt.Errorf("read action: %w", err)
	}
	if len(raw) > 8*1024*1024 {
		return ExitInvalid, errors.New("action input exceeds 8388608 bytes")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	decoder.DisallowUnknownFields()
	var event action.Action
	if err := decoder.Decode(&event); err != nil {
		return ExitInvalid, fmt.Errorf("decode action: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return ExitInvalid, errors.New("decode action: multiple JSON values are not supported")
		}
		return ExitInvalid, fmt.Errorf("decode action trailing content: %w", err)
	}
	event.Normalize()
	analyze.Enrich(&event)
	if err := event.Validate(); err != nil {
		return ExitInvalid, err
	}
	decision, err := eng.Decide(ctx, *observer, event, *native)
	if err != nil {
		return ExitInternal, err
	}
	if err := writeJSON(a.Stdout, decision); err != nil {
		return ExitInternal, err
	}
	switch decision.Decision {
	case policy.DecisionDeny:
		return ExitDenied, nil
	case policy.DecisionAsk:
		return ExitApproval, nil
	default:
		return ExitOK, nil
	}
}

func (a *App) runHook(ctx context.Context, args []string) (int, error) {
	fs := flag.NewFlagSet("hook", flag.ContinueOnError)
	fs.SetOutput(a.Stderr)
	policyPath, dataDir := commonFlags(fs)
	host := fs.String("host", "", "codex, claude, or openclaw")
	if err := fs.Parse(args); err != nil {
		return ExitInvalid, err
	}
	input, decodeErr := adapter.Decode(a.Stdin)
	if decodeErr != nil {
		fallback := adapter.FailClosed(*host, "PreToolUse")
		_ = writeJSON(a.Stdout, fallback)
		return ExitOK, decodeErr
	}
	eng, loadErr := loadEngine(*policyPath, *dataDir)
	if loadErr != nil {
		fallback := adapter.FailClosed(*host, input.HookEventName)
		_ = writeJSON(a.Stdout, fallback)
		return ExitOK, loadErr
	}
	result, handleErr := (&adapter.Handler{Engine: eng}).Handle(ctx, *host, input)
	if handleErr != nil {
		fallback := adapter.FailClosed(*host, input.HookEventName)
		_ = writeJSON(a.Stdout, fallback)
		return ExitOK, handleErr
	}
	if err := writeJSON(a.Stdout, result); err != nil {
		return ExitOK, err
	}
	return ExitOK, nil
}

func (a *App) runPolicy(args []string) (int, error) {
	if len(args) == 0 || args[0] != "validate" {
		return ExitInvalid, errors.New("usage: agent-firewall policy validate [PATH]")
	}
	path := ""
	if len(args) > 1 {
		path = args[1]
	}
	resolved, err := resolvePolicyPath(path)
	if err != nil {
		return ExitInvalid, err
	}
	loaded, err := policy.Load(resolved)
	if err != nil {
		return ExitInvalid, err
	}
	return ExitOK, writeJSON(a.Stdout, map[string]any{
		"valid": true, "path": resolved, "name": loaded.Name, "digest": loaded.Digest, "rules": len(loaded.Rules),
	})
}

func (a *App) runApprovals(ctx context.Context, args []string) (int, error) {
	if len(args) == 0 {
		return ExitInvalid, errors.New("usage: agent-firewall approvals list|approve|deny")
	}
	fs := flag.NewFlagSet("approvals "+args[0], flag.ContinueOnError)
	fs.SetOutput(a.Stderr)
	dataDir := fs.String("data-dir", "", "runtime data directory")
	includeResolved := fs.Bool("all", false, "include resolved approvals")
	if err := fs.Parse(args[1:]); err != nil {
		return ExitInvalid, err
	}
	store := approval.New(resolveDataDir(*dataDir), 10*time.Minute)
	switch args[0] {
	case "list":
		requests, err := store.List(ctx, *includeResolved)
		if err != nil {
			return ExitInternal, err
		}
		return ExitOK, writeJSON(a.Stdout, requests)
	case "approve", "deny":
		remaining := fs.Args()
		if len(remaining) != 1 {
			return ExitInvalid, fmt.Errorf("usage: agent-firewall approvals %s [--data-dir PATH] ID", args[0])
		}
		request, err := store.Resolve(ctx, remaining[0], args[0] == "approve")
		if err != nil {
			return ExitInvalid, err
		}
		return ExitOK, writeJSON(a.Stdout, request)
	default:
		return ExitInvalid, fmt.Errorf("unknown approvals command %q", args[0])
	}
}

func (a *App) runAudit(args []string) (int, error) {
	if len(args) == 0 {
		return ExitInvalid, errors.New("usage: agent-firewall audit list|verify|export|replay")
	}
	fs := flag.NewFlagSet("audit "+args[0], flag.ContinueOnError)
	fs.SetOutput(a.Stderr)
	policyPath, dataDir := commonFlags(fs)
	limit := fs.Int("limit", 50, "maximum recent events")
	trustedHead := fs.String("trusted-head", "", "expected ledger head hash")
	if err := fs.Parse(args[1:]); err != nil {
		return ExitInvalid, err
	}
	ledger := audit.New(resolveDataDir(*dataDir))
	switch args[0] {
	case "list":
		events, err := ledger.Events(*limit)
		if err != nil {
			return ExitInternal, err
		}
		return ExitOK, writeJSON(a.Stdout, events)
	case "verify":
		report := ledger.Verify(*trustedHead)
		if err := writeJSON(a.Stdout, report); err != nil {
			return ExitInternal, err
		}
		if !report.Valid {
			return ExitDenied, nil
		}
		return ExitOK, nil
	case "export":
		if err := ledger.Export(a.Stdout); err != nil {
			return ExitInternal, err
		}
		return ExitOK, nil
	case "replay":
		resolved, err := resolvePolicyPath(*policyPath)
		if err != nil {
			return ExitInvalid, err
		}
		loaded, err := policy.Load(resolved)
		if err != nil {
			return ExitInvalid, err
		}
		events, err := ledger.Events(0)
		if err != nil {
			return ExitInternal, err
		}
		return a.replay(loaded, events)
	default:
		return ExitInvalid, fmt.Errorf("unknown audit command %q", args[0])
	}
}

func (a *App) replay(loaded *policy.Policy, events []audit.Event) (int, error) {
	type drift struct {
		Sequence uint64               `json:"sequence"`
		Before   policy.DecisionValue `json:"before"`
		After    policy.DecisionValue `json:"after"`
		RuleID   string               `json:"rule_id"`
	}
	var drifts []drift
	replayed := 0
	for _, event := range events {
		if event.Type != "decision" || event.Action == nil || event.Decision == nil {
			continue
		}
		decision, err := loaded.Evaluate(*event.Action)
		if err != nil {
			return ExitInternal, fmt.Errorf("replay event %d: %w", event.Sequence, err)
		}
		replayed++
		before := replayBaseline(event.Decision)
		if decision.Decision != before {
			drifts = append(drifts, drift{Sequence: event.Sequence, Before: before, After: decision.Decision, RuleID: decision.RuleID})
		}
	}
	result := map[string]any{"replayed": replayed, "drift_count": len(drifts), "drifts": drifts, "policy_digest": loaded.Digest}
	if err := writeJSON(a.Stdout, result); err != nil {
		return ExitInternal, err
	}
	return ExitOK, nil
}

func replayBaseline(summary *audit.DecisionSummary) policy.DecisionValue {
	if strings.HasPrefix(summary.RuleID, "approved:") || strings.HasPrefix(summary.RuleID, "human-denied:") {
		return policy.DecisionAsk
	}
	return summary.Value
}

func (a *App) runMCP(ctx context.Context, args []string) (int, error) {
	if len(args) == 0 || args[0] != "proxy" {
		return ExitInvalid, errors.New("usage: agent-firewall mcp proxy [flags] -- COMMAND [ARG...]")
	}
	fs := flag.NewFlagSet("mcp proxy", flag.ContinueOnError)
	fs.SetOutput(a.Stderr)
	policyPath, dataDir := commonFlags(fs)
	workspace := fs.String("workspace", "", "workspace for policy scope")
	if err := fs.Parse(args[1:]); err != nil {
		return ExitInvalid, err
	}
	upstream := fs.Args()
	if len(upstream) == 0 {
		return ExitInvalid, errors.New("MCP upstream command is required after --")
	}
	if *workspace == "" {
		current, err := os.Getwd()
		if err != nil {
			return ExitInternal, err
		}
		*workspace = current
	}
	eng, err := loadEngine(*policyPath, *dataDir)
	if err != nil {
		return ExitInvalid, err
	}
	proxy := &mcpproxy.Proxy{Engine: eng, Workspace: *workspace}
	if err := proxy.Run(ctx, a.Stdin, a.Stdout, a.Stderr, upstream[0], upstream[1:]...); err != nil {
		return ExitInternal, err
	}
	return ExitOK, nil
}

func (a *App) runDoctor(args []string) (int, error) {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(a.Stderr)
	policyPath, dataDir := commonFlags(fs)
	if err := fs.Parse(args); err != nil {
		return ExitInvalid, err
	}
	resolvedPolicy, err := resolvePolicyPath(*policyPath)
	checks := map[string]any{"version": Version}
	healthy := true
	if err != nil {
		checks["policy"] = map[string]any{"ok": false, "error": err.Error()}
		healthy = false
	} else if loaded, loadErr := policy.Load(resolvedPolicy); loadErr != nil {
		checks["policy"] = map[string]any{"ok": false, "error": loadErr.Error(), "path": resolvedPolicy}
		healthy = false
	} else {
		checks["policy"] = map[string]any{"ok": true, "path": resolvedPolicy, "digest": loaded.Digest}
	}
	resolvedData := resolveDataDir(*dataDir)
	if mkdirErr := os.MkdirAll(resolvedData, 0o700); mkdirErr != nil {
		checks["data_dir"] = map[string]any{"ok": false, "error": mkdirErr.Error(), "path": resolvedData}
		healthy = false
	} else {
		checks["data_dir"] = map[string]any{"ok": true, "path": resolvedData}
	}
	verify := audit.New(resolvedData).Verify("")
	checks["audit"] = verify
	if !verify.Valid {
		healthy = false
	}
	checks["healthy"] = healthy
	if err := writeJSON(a.Stdout, checks); err != nil {
		return ExitInternal, err
	}
	if !healthy {
		return ExitDenied, nil
	}
	return ExitOK, nil
}

func commonFlags(fs *flag.FlagSet) (*string, *string) {
	policyPath := fs.String("policy", "", "policy path")
	dataDir := fs.String("data-dir", "", "runtime data directory")
	return policyPath, dataDir
}

func loadEngine(policyPath, dataDir string) (*engine.Engine, error) {
	resolvedPolicy, err := resolvePolicyPath(policyPath)
	if err != nil {
		return nil, err
	}
	loaded, err := policy.Load(resolvedPolicy)
	if err != nil {
		return nil, err
	}
	resolvedData := resolveDataDir(dataDir)
	return &engine.Engine{
		Policy: loaded, Approvals: approval.New(resolvedData, 10*time.Minute), Ledger: audit.New(resolvedData),
	}, nil
}

func resolvePolicyPath(path string) (string, error) {
	if path == "" {
		path = os.Getenv("AFW_POLICY")
	}
	if path != "" {
		abs, err := filepath.Abs(path)
		if err != nil {
			return "", err
		}
		return abs, nil
	}
	current, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		candidate := filepath.Join(current, "agent-firewall.yaml")
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		current = parent
	}
	return "", errors.New("agent-firewall.yaml not found; pass --policy or run agent-firewall init")
}

func resolveDataDir(path string) string {
	if path == "" {
		path = os.Getenv("AFW_DATA_DIR")
	}
	if path != "" {
		if abs, err := filepath.Abs(path); err == nil {
			return abs
		}
		return path
	}
	if base, err := os.UserConfigDir(); err == nil {
		return filepath.Join(base, "agent-firewall")
	}
	return filepath.Join(os.TempDir(), "agent-firewall")
}

func hookSnippet(command string) map[string]any {
	hook := func(event string) map[string]any {
		return map[string]any{
			"matcher": ".*",
			"hooks":   []any{map[string]any{"type": "command", "command": command, "timeout": 10}},
		}
	}
	return map[string]any{
		"PreToolUse":        []any{hook("PreToolUse")},
		"PermissionRequest": []any{hook("PermissionRequest")},
		"PostToolUse":       []any{hook("PostToolUse")},
	}
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func writeJSON(writer io.Writer, value any) error {
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	return encoder.Encode(value)
}

func (a *App) usage() {
	fmt.Fprintln(a.Stderr, `Agent Firewall - local-first policy and evidence for agent actions

Usage:
  agent-firewall init [--policy PATH]
  agent-firewall check [--policy PATH] [--input PATH|-]
  agent-firewall hook --host codex|claude|openclaw [--policy PATH]
  agent-firewall mcp proxy [flags] -- COMMAND [ARG...]
  agent-firewall approvals list|approve|deny
  agent-firewall audit list|verify|export|replay
  agent-firewall policy validate [PATH]
  agent-firewall doctor
  agent-firewall version`)
}
