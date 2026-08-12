package adapter

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/YuYigeng/agent-firewall/internal/approval"
	"github.com/YuYigeng/agent-firewall/internal/audit"
	"github.com/YuYigeng/agent-firewall/internal/engine"
	"github.com/YuYigeng/agent-firewall/internal/policy"
)

func TestDecodeRejectsTrailingJSON(t *testing.T) {
	_, err := Decode(strings.NewReader(`{"cwd":"/tmp","tool_name":"Bash"} {"tool_name":"Write"}`))
	if err == nil {
		t.Fatal("expected trailing JSON to be rejected")
	}
}

func TestCodexAskFailsClosedWithOneShotApproval(t *testing.T) {
	handler, store := testHandler(t)
	input := HookInput{
		SessionID: "session", CWD: t.TempDir(), HookEventName: "PreToolUse", ToolName: "Bash", ToolUseID: "call-1",
		ToolInput: map[string]any{"command": "npm install left-pad"},
	}
	result, err := handler.Handle(context.Background(), "codex", input)
	if err != nil {
		t.Fatal(err)
	}
	decision := nestedString(result, "hookSpecificOutput", "permissionDecision")
	if decision != "deny" {
		t.Fatalf("permissionDecision = %q", decision)
	}
	requests, err := store.List(context.Background(), false)
	if err != nil || len(requests) != 1 {
		t.Fatalf("requests=%v err=%v", requests, err)
	}
	if _, err := store.Resolve(context.Background(), requests[0].ID, true); err != nil {
		t.Fatal(err)
	}
	input.ToolUseID = "call-2"
	result, err = handler.Handle(context.Background(), "codex", input)
	if err != nil {
		t.Fatal(err)
	}
	decision = nestedString(result, "hookSpecificOutput", "permissionDecision")
	if decision != "allow" {
		t.Fatalf("approved retry = %q", decision)
	}
}

func TestClaudeUsesNativeAskAndCriticalDeny(t *testing.T) {
	handler, _ := testHandler(t)
	workspace := t.TempDir()
	ask, err := handler.Handle(context.Background(), "claude", HookInput{
		CWD: workspace, HookEventName: "PreToolUse", ToolName: "Bash",
		ToolInput: map[string]any{"command": "npm install left-pad"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := nestedString(ask, "hookSpecificOutput", "permissionDecision"); got != "ask" {
		t.Fatalf("ask decision = %q", got)
	}
	deny, err := handler.Handle(context.Background(), "claude", HookInput{
		CWD: workspace, HookEventName: "PreToolUse", ToolName: "Bash",
		ToolInput: map[string]any{"command": "rm -rf /"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := nestedString(deny, "hookSpecificOutput", "permissionDecision"); got != "deny" {
		t.Fatalf("deny decision = %q", got)
	}
}

func TestPostToolUseRecordsCompletion(t *testing.T) {
	handler, _ := testHandler(t)
	workspace := t.TempDir()
	result, err := handler.Handle(context.Background(), "claude", HookInput{
		CWD: workspace, HookEventName: "PostToolUse", ToolName: "Bash", ToolUseID: "call",
		ToolInput: map[string]any{"command": "git status"}, ToolResponse: map[string]any{"success": true}, DurationMS: 12,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result == nil {
		t.Fatal("missing hook result")
	}
}

func testHandler(t *testing.T) (*Handler, *approval.Store) {
	t.Helper()
	loaded, err := policy.Parse([]byte(policy.DefaultPolicy))
	if err != nil {
		t.Fatal(err)
	}
	dataDir := t.TempDir()
	store := approval.New(dataDir, time.Minute)
	eng := &engine.Engine{Policy: loaded, Approvals: store, Ledger: audit.New(dataDir)}
	return &Handler{Engine: eng}, store
}

func nestedString(value any, keys ...string) string {
	current := value
	for _, key := range keys {
		object, ok := current.(map[string]any)
		if !ok {
			return ""
		}
		current = object[key]
	}
	text, _ := current.(string)
	return text
}
