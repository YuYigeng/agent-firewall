package mcpproxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/YuYigeng/agent-firewall/internal/action"
	"github.com/YuYigeng/agent-firewall/internal/analyze"
	"github.com/YuYigeng/agent-firewall/internal/engine"
	"github.com/YuYigeng/agent-firewall/internal/policy"
)

const maxFrameSize = 16 * 1024 * 1024

type Proxy struct {
	Engine    *engine.Engine
	Workspace string
}

type rpcMessage struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   json.RawMessage `json:"error,omitempty"`
}

type toolCallParams struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments"`
}

type pendingCall struct {
	action action.Action
	start  time.Time
}

func (p *Proxy) Run(ctx context.Context, input io.Reader, output, diagnostics io.Writer, command string, args ...string) error {
	if p.Engine == nil {
		return errors.New("MCP proxy engine is required")
	}
	if strings.TrimSpace(command) == "" {
		return errors.New("MCP upstream command is required")
	}
	workspace, err := filepath.Abs(p.Workspace)
	if err != nil {
		return fmt.Errorf("resolve MCP workspace: %w", err)
	}
	cmd := exec.CommandContext(ctx, command, args...)
	upstreamIn, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	upstreamOut, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	cmd.Stderr = diagnostics
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start MCP upstream: %w", err)
	}

	var outputMu sync.Mutex
	var pendingMu sync.Mutex
	pending := map[string]pendingCall{}
	upstreamDone := make(chan error, 1)
	go func() {
		upstreamDone <- p.forwardUpstream(ctx, upstreamOut, output, diagnostics, &outputMu, &pendingMu, pending)
	}()

	clientErr := p.forwardClient(ctx, input, upstreamIn, output, diagnostics, &outputMu, &pendingMu, pending, workspace, filepath.Base(command))
	closeErr := upstreamIn.Close()
	upstreamErr := <-upstreamDone
	waitErr := cmd.Wait()
	if clientErr != nil {
		return clientErr
	}
	if closeErr != nil {
		return closeErr
	}
	if upstreamErr != nil {
		return upstreamErr
	}
	if waitErr != nil {
		return fmt.Errorf("MCP upstream exited: %w", waitErr)
	}
	return nil
}

func (p *Proxy) forwardClient(
	ctx context.Context,
	input io.Reader,
	upstream io.Writer,
	output, diagnostics io.Writer,
	outputMu, pendingMu *sync.Mutex,
	pending map[string]pendingCall,
	workspace, serverName string,
) error {
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 64*1024), maxFrameSize)
	for scanner.Scan() {
		frame := append([]byte(nil), scanner.Bytes()...)
		var message rpcMessage
		if err := decodeFrame(frame, &message); err != nil {
			return fmt.Errorf("invalid MCP client frame: %w", err)
		}
		if message.Method != "tools/call" {
			if err := writeFrame(upstream, frame, nil); err != nil {
				return err
			}
			continue
		}
		var params toolCallParams
		decoder := json.NewDecoder(bytes.NewReader(message.Params))
		decoder.UseNumber()
		if err := decoder.Decode(&params); err != nil || strings.TrimSpace(params.Name) == "" {
			decision := localError(message.ID, policy.DecisionDeny, "invalid-tools-call", "Malformed MCP tools/call blocked", "", action.RiskHigh)
			if err := writeFrame(output, decision, outputMu); err != nil {
				return err
			}
			continue
		}
		toolName := "mcp__" + safeName(serverName) + "__" + params.Name
		a, err := analyze.Normalize(analyze.Input{
			Source: "mcp", CallID: rawID(message.ID), Workspace: workspace,
			ToolName: toolName, ToolInput: params.Arguments, OccurredAt: time.Now().UTC(),
		})
		if err != nil {
			decision := localError(message.ID, policy.DecisionDeny, "normalization-error", "MCP tool call could not be normalized", "", action.RiskHigh)
			if err := writeFrame(output, decision, outputMu); err != nil {
				return err
			}
			continue
		}
		decision, err := p.Engine.Decide(ctx, "mcp-stdio-proxy", a, false)
		if err != nil {
			decisionFrame := localError(message.ID, policy.DecisionDeny, "internal-fail-closed", "Agent Firewall failed closed", "", action.RiskCritical)
			if err := writeFrame(output, decisionFrame, outputMu); err != nil {
				return err
			}
			fmt.Fprintf(diagnostics, "agent-firewall: MCP evaluation failed: %v\n", err)
			continue
		}
		if decision.Decision != policy.DecisionAllow {
			decisionFrame := localError(message.ID, decision.Decision, decision.RuleID, decision.Reason, decision.ApprovalID, decision.Risk)
			if err := writeFrame(output, decisionFrame, outputMu); err != nil {
				return err
			}
			continue
		}
		if len(message.ID) > 0 && string(message.ID) != "null" {
			pendingMu.Lock()
			pending[idKey(message.ID)] = pendingCall{action: a, start: time.Now()}
			pendingMu.Unlock()
		}
		if err := writeFrame(upstream, frame, nil); err != nil {
			return err
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read MCP client: %w", err)
	}
	return nil
}

func (p *Proxy) forwardUpstream(
	ctx context.Context,
	upstream io.Reader,
	output, diagnostics io.Writer,
	outputMu, pendingMu *sync.Mutex,
	pending map[string]pendingCall,
) error {
	scanner := bufio.NewScanner(upstream)
	scanner.Buffer(make([]byte, 64*1024), maxFrameSize)
	for scanner.Scan() {
		frame := append([]byte(nil), scanner.Bytes()...)
		var message rpcMessage
		if err := decodeFrame(frame, &message); err != nil {
			return fmt.Errorf("invalid MCP upstream frame: %w", err)
		}
		if len(message.ID) > 0 && string(message.ID) != "null" && message.Method == "" {
			key := idKey(message.ID)
			pendingMu.Lock()
			call, ok := pending[key]
			if ok {
				delete(pending, key)
			}
			pendingMu.Unlock()
			if ok {
				metadata := map[string]any{
					"duration_ms": time.Since(call.start).Milliseconds(),
					"completed":   true,
					"is_error":    len(message.Error) > 0 && string(message.Error) != "null",
				}
				if err := p.Engine.RecordCompletion(ctx, "mcp-stdio-proxy", call.action, metadata); err != nil {
					fmt.Fprintf(diagnostics, "agent-firewall: MCP completion evidence failed: %v\n", err)
				}
			}
		}
		if err := writeFrame(output, frame, outputMu); err != nil {
			return err
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read MCP upstream: %w", err)
	}
	return nil
}

func decodeFrame(frame []byte, target any) error {
	if len(bytes.TrimSpace(frame)) == 0 {
		return errors.New("empty JSON-RPC frame")
	}
	if bytes.HasPrefix(bytes.TrimSpace(frame), []byte("[")) {
		return errors.New("JSON-RPC batches are not supported by the v0.1 proxy")
	}
	decoder := json.NewDecoder(bytes.NewReader(frame))
	decoder.UseNumber()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return errors.New("multiple JSON values in one JSON-RPC frame")
		}
		return fmt.Errorf("trailing JSON-RPC content: %w", err)
	}
	return nil
}

func localError(id json.RawMessage, decision policy.DecisionValue, ruleID, reason, approvalID string, risk action.Risk) []byte {
	code := -32001
	if decision == policy.DecisionAsk {
		code = -32002
	}
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	response := struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Error   struct {
			Code    int            `json:"code"`
			Message string         `json:"message"`
			Data    map[string]any `json:"data"`
		} `json:"error"`
	}{JSONRPC: "2.0", ID: id}
	response.Error.Code = code
	response.Error.Message = reason
	response.Error.Data = map[string]any{
		"firewall_decision": decision,
		"rule_id":           ruleID,
		"risk":              risk,
	}
	if approvalID != "" {
		response.Error.Data["approval_id"] = approvalID
		response.Error.Data["next_step"] = "Approve the id with agent-firewall, then retry the identical tools/call"
	}
	raw, _ := json.Marshal(response)
	return raw
}

func writeFrame(writer io.Writer, frame []byte, lock *sync.Mutex) error {
	if lock != nil {
		lock.Lock()
		defer lock.Unlock()
	}
	if _, err := writer.Write(frame); err != nil {
		return err
	}
	_, err := writer.Write([]byte{'\n'})
	return err
}

func idKey(id json.RawMessage) string {
	return string(bytes.TrimSpace(id))
}

func rawID(id json.RawMessage) string {
	return strings.Trim(string(id), "\"")
}

func safeName(value string) string {
	value = strings.ToLower(value)
	var builder strings.Builder
	for _, char := range value {
		if (char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') || char == '_' || char == '-' {
			builder.WriteRune(char)
		} else {
			builder.WriteByte('_')
		}
	}
	if builder.Len() == 0 {
		return "stdio"
	}
	return builder.String()
}
