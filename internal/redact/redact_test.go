package redact

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/YuYigeng/agent-firewall/internal/action"
)

func TestActionRedactsSecrets(t *testing.T) {
	const fakeSecret = "ghp_1234567890abcdefghijklmnop"
	input := action.Action{
		Schema: action.Schema, Source: "test", SessionID: fakeSecret, Workspace: t.TempDir(),
		Kind: action.KindTool, Operation: "send", Risk: action.RiskHigh,
		Attributes: map[string]any{
			"authorization": "Bearer abcdefghijklmnopqrstuvwxyz",
			"arguments":     map[string]any{"body": "token=" + fakeSecret},
		},
	}
	output, report := Action(input)
	raw, err := json.Marshal(output)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), fakeSecret) || strings.Contains(string(raw), "abcdefghijklmnopqrstuvwxyz") {
		t.Fatalf("secret remained in %s", raw)
	}
	if len(report) == 0 {
		t.Fatal("expected redaction report")
	}
}
