package audit

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/YuYigeng/agent-firewall/internal/action"
	"github.com/YuYigeng/agent-firewall/internal/policy"
)

func TestLedgerRedactionAndTamperDetection(t *testing.T) {
	const fakeSecret = "ghp_1234567890abcdefghijklmnop"
	dataDir := t.TempDir()
	ledger := New(dataDir)
	event := action.Action{
		Schema: action.Schema, Source: "test", Workspace: "/work", Kind: action.KindShell,
		Operation: "curl", Risk: action.RiskHigh,
		Attributes: map[string]any{"command": "curl -H 'Authorization: Bearer " + fakeSecret + "' https://example.com"},
	}
	event.Normalize()
	fingerprint, err := event.Fingerprint()
	if err != nil {
		t.Fatal(err)
	}
	decision := policy.Decision{
		Schema: "afw.decision/v1alpha1", Decision: policy.DecisionDeny, Risk: action.RiskHigh,
		RuleID: "test", Reason: "secret " + fakeSecret, ActionFingerprint: fingerprint, PolicyDigest: "sha256:policy",
	}
	if _, err := ledger.AppendDecision(context.Background(), "test", event, decision); err != nil {
		t.Fatal(err)
	}
	if report := ledger.Verify(""); !report.Valid || report.Events != 1 {
		t.Fatalf("verify = %#v", report)
	}
	raw, err := os.ReadFile(filepath.Join(dataDir, "audit", "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), fakeSecret) {
		t.Fatalf("ledger leaked fake secret: %s", raw)
	}
	var stored Event
	if err := json.Unmarshal(raw[:len(raw)-1], &stored); err != nil {
		t.Fatal(err)
	}
	stored.Observer = "tampered"
	tampered, _ := json.Marshal(stored)
	if err := os.WriteFile(filepath.Join(dataDir, "audit", "events.jsonl"), append(tampered, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if report := ledger.Verify(""); report.Valid {
		t.Fatal("tampering was not detected")
	}
}
