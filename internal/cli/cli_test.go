package cli

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/YuYigeng/agent-firewall/internal/action"
	"github.com/YuYigeng/agent-firewall/internal/analyze"
	"github.com/YuYigeng/agent-firewall/internal/audit"
	"github.com/YuYigeng/agent-firewall/internal/policy"
)

func TestReplayTreatsHumanOverrideAsAskBaseline(t *testing.T) {
	loaded, err := policy.Parse([]byte(policy.DefaultPolicy))
	if err != nil {
		t.Fatal(err)
	}
	event, err := analyze.Normalize(analyze.Input{
		Source: "codex", Workspace: t.TempDir(), ToolName: "Bash",
		ToolInput: map[string]any{"command": "npm install left-pad"},
	})
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	app := &App{Stdout: &output}
	code, err := app.replay(loaded, []audit.Event{{
		Sequence: 1, Type: "decision", Action: &event,
		Decision: &audit.DecisionSummary{Value: policy.DecisionAllow, RuleID: "approved:ask-package-install"},
	}})
	if err != nil || code != ExitOK {
		t.Fatalf("code=%d err=%v", code, err)
	}
	var result struct {
		DriftCount int `json:"drift_count"`
		Replayed   int `json:"replayed"`
	}
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.DriftCount != 0 || result.Replayed != 1 {
		t.Fatalf("result=%+v", result)
	}
}

func TestReplayBaseline(t *testing.T) {
	tests := []struct {
		rule string
		got  policy.DecisionValue
	}{
		{rule: "approved:ask-package-install", got: policy.DecisionAsk},
		{rule: "human-denied:ask-package-install", got: policy.DecisionAsk},
		{rule: "deny-destructive-root", got: policy.DecisionDeny},
	}
	for _, test := range tests {
		summary := &audit.DecisionSummary{Value: policy.DecisionDeny, RuleID: test.rule, Risk: action.RiskHigh}
		if got := replayBaseline(summary); got != test.got {
			t.Fatalf("rule=%s got=%s want=%s", test.rule, got, test.got)
		}
	}
}
