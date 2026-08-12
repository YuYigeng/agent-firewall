package policy

import (
	"strings"
	"testing"

	"github.com/YuYigeng/agent-firewall/internal/action"
	"github.com/YuYigeng/agent-firewall/internal/analyze"
)

func TestDefaultPolicyDecisions(t *testing.T) {
	loaded, err := Parse([]byte(DefaultPolicy))
	if err != nil {
		t.Fatal(err)
	}
	workspace := t.TempDir()
	tests := []struct {
		name     string
		tool     string
		input    map[string]any
		decision DecisionValue
		rule     string
	}{
		{name: "safe shell", tool: "Bash", input: map[string]any{"command": "git status"}, decision: DecisionAllow, rule: "default-low"},
		{name: "root delete", tool: "Bash", input: map[string]any{"command": "rm -rf /"}, decision: DecisionDeny, rule: "deny-destructive-root"},
		{name: "package install", tool: "Bash", input: map[string]any{"command": "npm install left-pad"}, decision: DecisionAsk, rule: "ask-package-install"},
		{name: "workspace write", tool: "Write", input: map[string]any{"file_path": workspace + "/ok.txt", "content": "ok"}, decision: DecisionAllow, rule: "allow-workspace-writes"},
		{name: "sensitive write", tool: "Write", input: map[string]any{"file_path": workspace + "/.env", "content": "X=1"}, decision: DecisionAsk, rule: "ask-sensitive-path"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			event, err := analyze.Normalize(analyze.Input{Source: "test", Workspace: workspace, ToolName: test.tool, ToolInput: test.input})
			if err != nil {
				t.Fatal(err)
			}
			decision, err := loaded.Evaluate(event)
			if err != nil {
				t.Fatal(err)
			}
			if decision.Decision != test.decision || decision.RuleID != test.rule {
				t.Fatalf("decision=%s rule=%s, want %s/%s; signals=%v", decision.Decision, decision.RuleID, test.decision, test.rule, event.Signals)
			}
		})
	}
}

func TestPolicyPriorityAndDenyPrecedence(t *testing.T) {
	raw := `version: afw.policy/v1alpha1
name: precedence
defaults: {low: allow, medium: ask, high: ask, critical: deny, on_error: deny}
rules:
  - id: allow
    priority: 10
    decision: allow
    match: {kinds: [shell]}
  - id: deny
    priority: 10
    decision: deny
    match: {kinds: [shell]}
  - id: high-allow
    priority: 20
    decision: allow
    match: {operations: [git]}
`
	loaded, err := Parse([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	event := action.Action{Schema: action.Schema, Source: "test", Workspace: t.TempDir(), Kind: action.KindShell, Operation: "git", Risk: action.RiskLow}
	event.Normalize()
	decision, err := loaded.Evaluate(event)
	if err != nil {
		t.Fatal(err)
	}
	if decision.RuleID != "high-allow" || decision.Decision != DecisionAllow {
		t.Fatalf("got %s/%s", decision.RuleID, decision.Decision)
	}
	event.Operation = "sh"
	decision, err = loaded.Evaluate(event)
	if err != nil {
		t.Fatal(err)
	}
	if decision.RuleID != "deny" || decision.Decision != DecisionDeny {
		t.Fatalf("got %s/%s", decision.RuleID, decision.Decision)
	}
}

func TestPolicyRejectsUnknownAndBadRegex(t *testing.T) {
	unknown := strings.Replace(DefaultPolicy, "name: balanced-local", "name: balanced-local\nunknown: true", 1)
	if _, err := Parse([]byte(unknown)); err == nil {
		t.Fatal("expected unknown field error")
	}
	bad := DefaultPolicy + "\n  - id: bad-regex\n    priority: 1\n    decision: deny\n    match:\n      command_regex: '[unterminated'\n"
	if _, err := Parse([]byte(bad)); err == nil {
		t.Fatal("expected regex error")
	}
}

func TestPolicyDigestIsSemantic(t *testing.T) {
	left, err := Parse([]byte(DefaultPolicy))
	if err != nil {
		t.Fatal(err)
	}
	right, err := Parse([]byte("\n# comment\n" + DefaultPolicy + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	if left.Digest != right.Digest {
		t.Fatalf("digest changed for comments: %s != %s", left.Digest, right.Digest)
	}
}

func TestPolicyRejectsMultipleDocuments(t *testing.T) {
	if _, err := Parse([]byte(DefaultPolicy + "\n---\nversion: afw.policy/v1alpha1\n")); err == nil {
		t.Fatal("expected multiple-document error")
	}
}

func FuzzPolicyParse(f *testing.F) {
	f.Add(DefaultPolicy)
	f.Add("version: afw.policy/v1alpha1\n")
	f.Add("---\n{}\n---\n{}\n")
	f.Fuzz(func(t *testing.T, raw string) {
		parsed, err := Parse([]byte(raw))
		if err == nil {
			if parsed.Digest == "" {
				t.Fatal("valid policy has no digest")
			}
			if _, err := Parse([]byte(raw)); err != nil {
				t.Fatalf("policy parse was not deterministic: %v", err)
			}
		}
	})
}
