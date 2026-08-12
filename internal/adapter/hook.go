package adapter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/YuYigeng/agent-firewall/internal/analyze"
	"github.com/YuYigeng/agent-firewall/internal/engine"
	"github.com/YuYigeng/agent-firewall/internal/policy"
)

const maxHookInput = 8 * 1024 * 1024

type HookInput struct {
	SessionID      string         `json:"session_id"`
	CWD            string         `json:"cwd"`
	HookEventName  string         `json:"hook_event_name"`
	ToolName       string         `json:"tool_name"`
	ToolUseID      string         `json:"tool_use_id"`
	ToolInput      map[string]any `json:"tool_input"`
	ToolResponse   any            `json:"tool_response"`
	DurationMS     int64          `json:"duration_ms"`
	Model          string         `json:"model"`
	PermissionMode string         `json:"permission_mode"`
	TurnID         string         `json:"turn_id"`

	OpenClawEvent string         `json:"event"`
	OpenClawTool  string         `json:"toolName"`
	OpenClawArgs  map[string]any `json:"params"`
	OpenClawRunID string         `json:"runId"`
}

type Handler struct {
	Engine *engine.Engine
}

func Decode(reader io.Reader) (HookInput, error) {
	raw, err := io.ReadAll(io.LimitReader(reader, maxHookInput+1))
	if err != nil {
		return HookInput{}, fmt.Errorf("read hook input: %w", err)
	}
	if len(raw) > maxHookInput {
		return HookInput{}, fmt.Errorf("hook input exceeds %d bytes", maxHookInput)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var input HookInput
	if err := decoder.Decode(&input); err != nil {
		return HookInput{}, fmt.Errorf("decode hook input: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return HookInput{}, fmt.Errorf("decode hook input: multiple JSON values are not supported")
		}
		return HookInput{}, fmt.Errorf("decode hook input trailing content: %w", err)
	}
	return input, nil
}

func (h *Handler) Handle(ctx context.Context, host string, input HookInput) (any, error) {
	host = strings.ToLower(strings.TrimSpace(host))
	if host != "codex" && host != "claude" && host != "openclaw" {
		return nil, fmt.Errorf("unsupported hook host %q", host)
	}
	if host == "openclaw" {
		if input.HookEventName == "" {
			input.HookEventName = input.OpenClawEvent
		}
		if input.ToolName == "" {
			input.ToolName = input.OpenClawTool
		}
		if input.ToolInput == nil {
			input.ToolInput = input.OpenClawArgs
		}
		if input.SessionID == "" {
			input.SessionID = input.OpenClawRunID
		}
	}
	if input.CWD == "" {
		return nil, fmt.Errorf("hook cwd is required")
	}
	if input.ToolName == "" {
		return nil, fmt.Errorf("hook tool_name is required")
	}
	if input.ToolInput == nil {
		input.ToolInput = map[string]any{}
	}
	a, err := analyze.Normalize(analyze.Input{
		Source: host, SessionID: input.SessionID, CallID: input.ToolUseID,
		Workspace: input.CWD, ToolName: input.ToolName, ToolInput: input.ToolInput,
		OccurredAt: time.Now().UTC(),
	})
	if err != nil {
		return nil, err
	}
	event := strings.ToLower(input.HookEventName)
	observer := host + "-hook"
	switch event {
	case "posttooluse", "after_tool_call", "post_tool_use":
		metadata := completionMetadata(input)
		if err := h.Engine.RecordCompletion(ctx, observer, a, metadata); err != nil {
			return nil, err
		}
		if host == "openclaw" {
			return map[string]any{"recorded": true}, nil
		}
		return map[string]any{}, nil
	case "permissionrequest", "permission_request":
		decision, err := h.Engine.Decide(ctx, observer, a, true)
		if err != nil {
			return nil, err
		}
		return permissionResult(host, decision), nil
	case "pretooluse", "before_tool_call", "pre_tool_use", "":
		nativeApproval := host == "claude" || host == "openclaw"
		decision, err := h.Engine.Decide(ctx, observer, a, nativeApproval)
		if err != nil {
			return nil, err
		}
		if host == "openclaw" {
			return decision, nil
		}
		return preToolResult(host, decision), nil
	default:
		return nil, fmt.Errorf("unsupported hook event %q", input.HookEventName)
	}
}

func FailClosed(host, event string) any {
	reason := "Agent Firewall failed closed because policy evaluation or evidence recording was unavailable."
	if strings.EqualFold(event, "PermissionRequest") || strings.EqualFold(event, "permission_request") {
		return map[string]any{
			"hookSpecificOutput": map[string]any{
				"hookEventName": "PermissionRequest",
				"decision":      map[string]any{"behavior": "deny", "message": reason},
			},
		}
	}
	if strings.EqualFold(event, "PostToolUse") || strings.EqualFold(event, "after_tool_call") {
		if host == "openclaw" {
			return map[string]any{"recorded": false, "error": "evidence-unavailable"}
		}
		return map[string]any{"systemMessage": reason}
	}
	if host == "openclaw" {
		return policy.Decision{
			Schema: "afw.decision/v1alpha1", Decision: policy.DecisionDeny,
			RuleID: "internal-fail-closed", Reason: reason,
		}
	}
	return map[string]any{
		"hookSpecificOutput": map[string]any{
			"hookEventName": "PreToolUse", "permissionDecision": "deny",
			"permissionDecisionReason": reason,
		},
	}
}

func preToolResult(host string, decision policy.Decision) any {
	value := string(decision.Decision)
	reason := decision.Reason
	if host == "codex" && decision.Decision == policy.DecisionAsk {
		value = "deny"
		reason = fmt.Sprintf("Approval required by Agent Firewall. Run `agent-firewall approvals approve %s`, then retry the identical action.", decision.ApprovalID)
	}
	return map[string]any{
		"hookSpecificOutput": map[string]any{
			"hookEventName": "PreToolUse", "permissionDecision": value,
			"permissionDecisionReason": reason,
		},
	}
}

func permissionResult(host string, decision policy.Decision) any {
	if decision.Decision == policy.DecisionAsk {
		if host == "openclaw" {
			return decision
		}
		return map[string]any{}
	}
	behavior := string(decision.Decision)
	if behavior == "ask" {
		behavior = "deny"
	}
	result := map[string]any{"behavior": behavior}
	if behavior == "deny" {
		result["message"] = decision.Reason
	}
	return map[string]any{
		"hookSpecificOutput": map[string]any{
			"hookEventName": "PermissionRequest", "decision": result,
		},
	}
}

func completionMetadata(input HookInput) map[string]any {
	metadata := map[string]any{"duration_ms": input.DurationMS, "completed": true}
	if response, ok := input.ToolResponse.(map[string]any); ok {
		if value, exists := response["isError"]; exists {
			metadata["is_error"] = value
		}
		if value, exists := response["success"]; exists {
			metadata["success"] = value
		}
		if value, exists := response["status"]; exists {
			metadata["status"] = value
		}
	}
	return metadata
}
