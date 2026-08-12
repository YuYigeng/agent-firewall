package analyze

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/YuYigeng/agent-firewall/internal/action"
	"mvdan.cc/sh/v3/syntax"
)

type Input struct {
	Source     string
	SessionID  string
	CallID     string
	Workspace  string
	ToolName   string
	ToolInput  map[string]any
	OccurredAt time.Time
}

var (
	urlPattern             = regexp.MustCompile("(?i)https?://[^\\s'\\\"`<>]+")
	secretRefPattern       = regexp.MustCompile(`(?i)(\.env(?:\.|\b)|\.ssh(?:/|\b)|\.aws/credentials|\.config/gcloud|keychain|security\s+find-(?:generic|internet)-password|\b(?:AWS|GITHUB|GITLAB|OPENAI|ANTHROPIC|AZURE|GOOGLE)_[A-Z0-9_]*(?:TOKEN|SECRET|KEY|PASSWORD)\b|\$(?:[A-Z0-9_]*(?:TOKEN|SECRET|KEY|PASSWORD)))`)
	destructiveRootPattern = regexp.MustCompile(`(?i)(\brm\s+(?:-[a-z]*r[a-z]*f[a-z]*|-[a-z]*f[a-z]*r[a-z]*)\s+(?:/|~|\$HOME)(?:\s|$)|\bmkfs(?:\.|\s)|\bdd\s+[^\n]*\bof=/dev/|:\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;)`)
	destructivePattern     = regexp.MustCompile(`(?i)(\brm\s+(?:-[a-z]*r|-[a-z]*f)|\bgit\s+(?:reset\s+--hard|clean\s+-[a-z]*f)|\btruncate\s+-s\s*0|\bDROP\s+(?:TABLE|DATABASE)\b)`)
	reverseShellPattern    = regexp.MustCompile(`(?i)(/dev/tcp/|\bnc(?:at)?\s+[^\n]*\s-e\s|\bsocat\s+[^\n]*(?:exec|system):|\bbash\s+-i\b|\bpython\w*\s+-c\s+[^\n]*(?:socket|pty\.spawn))`)
	privilegePattern       = regexp.MustCompile(`(?i)(^|[;&|]\s*|\s)(sudo|doas)\s|\bchmod\s+(?:-R\s+)?777\b|\bchown\s+(?:-R\s+)?root\b`)
	persistencePattern     = regexp.MustCompile(`(?i)(\bcrontab\b|\blaunchctl\b|\bsystemctl\s+enable\b|/(?:etc/(?:profile|cron)|\.git/hooks/)|/(?:\.zshrc|\.bashrc|\.profile)\b)`)
	networkCommandPattern  = regexp.MustCompile(`(?i)(^|[;&|]\s*|\s)(curl|wget|fetch|nc|ncat|socat|ssh|scp|sftp|rsync)\s`)
	networkWritePattern    = regexp.MustCompile(`(?i)(\bcurl\b[^\n]*(?:\s-X\s*(?:POST|PUT|PATCH|DELETE)\b|--request\s+(?:POST|PUT|PATCH|DELETE)\b|\s(?:-d|--data(?:-[a-z-]+)?|-F|--form|-T|--upload-file)\s)|(^|[;&|]\s*|\s)(?:scp|sftp|rsync|nc|ncat|socat)\s)`)
	packageInstallPattern  = regexp.MustCompile(`(?i)(^|[;&|]\s*|\s)(?:npm|pnpm|yarn|bun|pip|pipx|uv|gem|cargo|go|brew|apt(?:-get)?|dnf|yum|pacman)\s+(?:add|install|get)\b`)
	protectedGitPattern    = regexp.MustCompile(`(?i)\bgit\s+push\b[^\n]*(?:--force(?:-with-lease)?|-f\b|\s(?:main|master)(?::|\s|$))`)
	dynamicShellPattern    = regexp.MustCompile(`(?i)(\b(?:eval|exec)\s+[^\n]*\$|\b(?:sh|bash|zsh)\s+-c\s+[^\n]*\$|\bbase64\s+(?:-d|--decode)[^|\n]*\|\s*(?:sh|bash|zsh))`)
	writeVerbPattern       = regexp.MustCompile(`(?i)(^|[_./:-])(create|write|edit|update|delete|remove|send|post|publish|deploy|execute|run|approve|pay|transfer|merge|push)([_./:-]|$)`)
	readVerbPattern        = regexp.MustCompile(`(?i)(^|[_./:-])(read|get|list|search|find|query|inspect|view|fetch|status|health)([_./:-]|$)`)
)

func Normalize(input Input) (action.Action, error) {
	workspace, err := filepath.Abs(input.Workspace)
	if err != nil {
		return action.Action{}, fmt.Errorf("resolve workspace: %w", err)
	}
	toolName := strings.TrimSpace(input.ToolName)
	if toolName == "" {
		return action.Action{}, fmt.Errorf("tool name is required")
	}
	if input.ToolInput == nil {
		input.ToolInput = map[string]any{}
	}

	a := action.Action{
		Schema:     action.Schema,
		ID:         input.CallID,
		Timestamp:  input.OccurredAt,
		Source:     input.Source,
		SessionID:  input.SessionID,
		Workspace:  workspace,
		Kind:       action.KindTool,
		Operation:  toolName,
		Attributes: map[string]any{"tool_name": toolName},
		Risk:       action.RiskLow,
	}

	lower := strings.ToLower(toolName)
	switch {
	case lower == "bash" || lower == "powershell" || lower == "exec_command" || lower == "shell":
		normalizeShell(&a, input.ToolInput)
	case lower == "apply_patch" || lower == "write" || lower == "edit" || lower == "multiedit":
		normalizeFile(&a, input.ToolInput, true)
	case lower == "read" || lower == "read_file" || lower == "view":
		normalizeFile(&a, input.ToolInput, false)
	case lower == "webfetch" || lower == "web_fetch" || lower == "http" || lower == "http_request":
		normalizeNetwork(&a, input.ToolInput)
	default:
		normalizeTool(&a, input.ToolInput)
	}

	a.Normalize()
	if err := a.Validate(); err != nil {
		return action.Action{}, err
	}
	return a, nil
}

func Enrich(a *action.Action) {
	if a.Attributes == nil {
		a.Attributes = map[string]any{}
	}
	toolName, _ := a.Attributes["tool_name"].(string)
	if toolName == "" {
		toolName = a.Operation
	}
	input := map[string]any{}
	if raw, ok := a.Attributes["arguments"].(map[string]any); ok {
		input = raw
	}
	switch a.Kind {
	case action.KindShell:
		if command, ok := a.Attributes["command"].(string); ok {
			normalizeShell(a, map[string]any{"command": command})
		}
	case action.KindFileRead:
		if len(input) == 0 {
			input = attributesAsInput(a.Attributes, "paths", "path", "file_path", "content", "command")
		}
		normalizeFile(a, input, false)
	case action.KindFileWrite:
		if len(input) == 0 {
			input = attributesAsInput(a.Attributes, "paths", "path", "file_path", "content", "command")
		}
		normalizeFile(a, input, true)
	case action.KindNetwork:
		if len(input) == 0 {
			input = attributesAsInput(a.Attributes, "url", "uri", "endpoint", "method", "http_method")
		}
		normalizeNetwork(a, input)
	case action.KindTool:
		a.Operation = toolName
		normalizeTool(a, input)
	}
	a.Normalize()
}

func attributesAsInput(attributes map[string]any, keys ...string) map[string]any {
	input := map[string]any{}
	for _, key := range keys {
		if value, ok := attributes[key]; ok {
			input[key] = value
		}
	}
	return input
}

func normalizeShell(a *action.Action, input map[string]any) {
	command := firstString(input, "command", "cmd", "script")
	a.Kind = action.KindShell
	a.Operation = firstCommand(command)
	if a.Operation == "" {
		a.Operation = "shell"
	}
	a.Subject = a.Operation
	a.Attributes["command"] = command
	a.Attributes["commands"] = shellCommands(command)
	addSignal(a, "shell", action.RiskLow)

	if destructiveRootPattern.MatchString(command) {
		addSignal(a, "destructive-root", action.RiskCritical)
	}
	if reverseShellPattern.MatchString(command) {
		addSignal(a, "reverse-shell", action.RiskCritical)
		addSignal(a, "network", action.RiskMedium)
	}
	if destructivePattern.MatchString(command) {
		addSignal(a, "destructive", action.RiskHigh)
	}
	if privilegePattern.MatchString(command) {
		addSignal(a, "privilege", action.RiskHigh)
	}
	if persistencePattern.MatchString(command) {
		addSignal(a, "persistence", action.RiskHigh)
	}
	if networkCommandPattern.MatchString(command) || urlPattern.MatchString(command) {
		addSignal(a, "network", action.RiskMedium)
	}
	if networkWritePattern.MatchString(command) {
		addSignal(a, "network-write", action.RiskHigh)
	}
	if packageInstallPattern.MatchString(command) {
		addSignal(a, "package-install", action.RiskMedium)
	}
	if protectedGitPattern.MatchString(command) {
		addSignal(a, "protected-git-write", action.RiskHigh)
	}
	if dynamicShellPattern.MatchString(command) {
		addSignal(a, "dynamic-shell", action.RiskHigh)
	}
	if secretRefPattern.MatchString(command) {
		addSignal(a, "secret-reference", action.RiskHigh)
	}
	urls := urlPattern.FindAllString(command, -1)
	if len(urls) > 0 {
		a.Attributes["urls"] = uniqueStrings(urls)
		for _, rawURL := range urls {
			if host, private, metadata := inspectURL(rawURL); host != "" {
				appendStringAttribute(a.Attributes, "hosts", host)
				if private {
					addSignal(a, "private-network", action.RiskHigh)
				}
				if metadata {
					addSignal(a, "cloud-metadata", action.RiskCritical)
				}
			}
		}
	}
	if a.HasSignal("network") && a.HasSignal("secret-reference") {
		addSignal(a, "potential-exfiltration", action.RiskCritical)
	}
}

func normalizeFile(a *action.Action, input map[string]any, write bool) {
	if write {
		a.Kind = action.KindFileWrite
	} else {
		a.Kind = action.KindFileRead
	}
	paths := filePaths(input)
	if len(paths) == 0 {
		paths = patchPaths(firstString(input, "command", "patch"))
	}
	absPaths := make([]string, 0, len(paths))
	outside := false
	for _, path := range paths {
		if !filepath.IsAbs(path) {
			path = filepath.Join(a.Workspace, path)
		}
		path = filepath.Clean(path)
		absPaths = append(absPaths, path)
		if !insideWorkspace(a.Workspace, path) {
			outside = true
		}
		lower := filepath.ToSlash(strings.ToLower(path))
		if secretRefPattern.MatchString(lower) {
			addSignal(a, "sensitive-path", action.RiskHigh)
		}
		if strings.Contains(lower, "/.git/hooks/") || strings.HasSuffix(lower, "/.zshrc") || strings.HasSuffix(lower, "/.bashrc") || strings.HasSuffix(lower, "/.profile") {
			addSignal(a, "persistence", action.RiskHigh)
		}
		if strings.Contains(lower, "/.codex/") || strings.Contains(lower, "/.claude/") || strings.Contains(lower, "/.openclaw/") {
			addSignal(a, "agent-config", action.RiskHigh)
		}
	}
	sort.Strings(absPaths)
	if len(absPaths) > 0 {
		a.Subject = absPaths[0]
		a.Attributes["paths"] = uniqueStrings(absPaths)
	}
	if outside {
		a.Attributes["path_scope"] = "outside-workspace"
		addSignal(a, "outside-workspace", action.RiskHigh)
	} else {
		a.Attributes["path_scope"] = "workspace"
	}
	if write {
		addSignal(a, "file-write", action.RiskLow)
	} else {
		addSignal(a, "file-read", action.RiskLow)
		if a.HasSignal("sensitive-path") {
			addSignal(a, "secret-reference", action.RiskHigh)
		}
	}
	if content := firstString(input, "content", "new_string", "patch", "command"); content != "" {
		if secretRefPattern.MatchString(content) || containsSecretLiteral(content) {
			addSignal(a, "secret-content", action.RiskHigh)
		}
		a.Attributes["content_bytes"] = len(content)
	}
}

func normalizeNetwork(a *action.Action, input map[string]any) {
	a.Kind = action.KindNetwork
	rawURL := firstString(input, "url", "uri", "endpoint")
	method := strings.ToUpper(firstString(input, "method", "http_method"))
	if method == "" {
		method = "GET"
	}
	a.Operation = method
	a.Subject = rawURL
	a.Attributes["method"] = method
	if rawURL != "" {
		a.Attributes["url"] = rawURL
	}
	addSignal(a, "network", action.RiskMedium)
	if method != "GET" && method != "HEAD" && method != "OPTIONS" {
		addSignal(a, "network-write", action.RiskHigh)
	}
	if host, private, metadata := inspectURL(rawURL); host != "" {
		a.Attributes["hosts"] = []string{host}
		if private {
			addSignal(a, "private-network", action.RiskHigh)
		}
		if metadata {
			addSignal(a, "cloud-metadata", action.RiskCritical)
		}
	}
	raw, _ := json.Marshal(input)
	if secretRefPattern.Match(raw) || containsSecretLiteral(string(raw)) {
		addSignal(a, "secret-reference", action.RiskHigh)
	}
	if a.HasSignal("secret-reference") {
		addSignal(a, "potential-exfiltration", action.RiskCritical)
	}
}

func normalizeTool(a *action.Action, input map[string]any) {
	a.Kind = action.KindTool
	a.Attributes["arguments"] = input
	lower := strings.ToLower(a.Operation)
	if strings.HasPrefix(lower, "mcp__") {
		addSignal(a, "mcp", action.RiskLow)
	}
	if writeVerbPattern.MatchString(lower) {
		addSignal(a, "state-changing-tool", action.RiskHigh)
	} else if !readVerbPattern.MatchString(lower) {
		addSignal(a, "unknown-tool", action.RiskMedium)
	}
	raw, _ := json.Marshal(input)
	text := string(raw)
	if secretRefPattern.Match(raw) || containsSecretLiteral(text) {
		addSignal(a, "secret-reference", action.RiskHigh)
	}
	if urlPattern.MatchString(text) {
		addSignal(a, "network", action.RiskMedium)
		for _, rawURL := range urlPattern.FindAllString(text, -1) {
			if host, private, metadata := inspectURL(rawURL); host != "" {
				appendStringAttribute(a.Attributes, "hosts", host)
				if private {
					addSignal(a, "private-network", action.RiskHigh)
				}
				if metadata {
					addSignal(a, "cloud-metadata", action.RiskCritical)
				}
			}
		}
	}
	if a.HasSignal("state-changing-tool") && a.HasSignal("network") {
		addSignal(a, "network-write", action.RiskHigh)
	}
	if a.HasSignal("network") && a.HasSignal("secret-reference") {
		addSignal(a, "potential-exfiltration", action.RiskCritical)
	}
}

func addSignal(a *action.Action, signal string, risk action.Risk) {
	if !a.HasSignal(signal) {
		a.Signals = append(a.Signals, signal)
	}
	a.Risk = action.MaxRisk(a.Risk, risk)
}

func firstString(input map[string]any, keys ...string) string {
	for _, key := range keys {
		if value, ok := input[key].(string); ok && value != "" {
			return value
		}
	}
	return ""
}

func firstCommand(command string) string {
	commands := shellCommands(command)
	if len(commands) == 0 {
		return ""
	}
	return commands[0]
}

func shellCommands(command string) []string {
	file, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(command), "")
	if err != nil {
		return fallbackCommands(command)
	}
	var commands []string
	syntax.Walk(file, func(node syntax.Node) bool {
		call, ok := node.(*syntax.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		word := call.Args[0]
		if len(word.Parts) == 1 {
			if literal, ok := word.Parts[0].(*syntax.Lit); ok {
				commands = append(commands, literal.Value)
			}
		}
		return true
	})
	return uniqueStrings(commands)
}

func fallbackCommands(command string) []string {
	parts := strings.Fields(command)
	if len(parts) == 0 {
		return nil
	}
	return []string{strings.Trim(parts[0], "'\"")}
}

func filePaths(input map[string]any) []string {
	var paths []string
	for _, key := range []string{"file_path", "path", "target", "destination"} {
		if value, ok := input[key].(string); ok && value != "" {
			paths = append(paths, value)
		}
	}
	if values, ok := input["paths"].([]any); ok {
		for _, value := range values {
			if path, ok := value.(string); ok && path != "" {
				paths = append(paths, path)
			}
		}
	}
	if values, ok := input["paths"].([]string); ok {
		paths = append(paths, values...)
	}
	return uniqueStrings(paths)
}

func patchPaths(patch string) []string {
	var paths []string
	for _, line := range strings.Split(patch, "\n") {
		line = strings.TrimSpace(line)
		for _, prefix := range []string{"*** Add File:", "*** Update File:", "*** Delete File:", "*** Move to:"} {
			if strings.HasPrefix(line, prefix) {
				path := strings.TrimSpace(strings.TrimPrefix(line, prefix))
				if path != "" {
					paths = append(paths, path)
				}
			}
		}
	}
	return uniqueStrings(paths)
}

func insideWorkspace(workspace, path string) bool {
	rel, err := filepath.Rel(filepath.Clean(workspace), filepath.Clean(path))
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}

func inspectURL(rawURL string) (host string, private bool, metadata bool) {
	parsed, err := url.Parse(strings.TrimRight(rawURL, ".,);]"))
	if err != nil {
		return "", false, false
	}
	host = strings.ToLower(parsed.Hostname())
	if host == "" {
		return "", false, false
	}
	metadata = host == "169.254.169.254" || host == "metadata.google.internal" || host == "metadata.azure.internal"
	ip := net.ParseIP(host)
	if ip != nil {
		private = ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()
	} else {
		private = host == "localhost" || strings.HasSuffix(host, ".localhost") || strings.HasSuffix(host, ".local")
	}
	return host, private, metadata
}

func containsSecretLiteral(value string) bool {
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		regexp.MustCompile(`gh[pousr]_[A-Za-z0-9_]{20,}`),
		regexp.MustCompile(`(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{12,}`),
		regexp.MustCompile(`\bsk-[A-Za-z0-9_-]{16,}`),
		regexp.MustCompile(`(?i)(?:token|secret|password|api[_-]?key)["']?\s*[:=]\s*["']?[A-Za-z0-9._~+/=-]{8,}`),
	}
	for _, pattern := range patterns {
		if pattern.MatchString(value) {
			return true
		}
	}
	return false
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func appendStringAttribute(attributes map[string]any, key, value string) {
	var values []string
	switch existing := attributes[key].(type) {
	case []string:
		values = existing
	case []any:
		for _, item := range existing {
			if text, ok := item.(string); ok {
				values = append(values, text)
			}
		}
	}
	values = append(values, value)
	attributes[key] = uniqueStrings(values)
}
