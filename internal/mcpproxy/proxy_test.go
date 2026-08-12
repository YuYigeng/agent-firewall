package mcpproxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/YuYigeng/agent-firewall/internal/approval"
	"github.com/YuYigeng/agent-firewall/internal/audit"
	"github.com/YuYigeng/agent-firewall/internal/engine"
	"github.com/YuYigeng/agent-firewall/internal/policy"
)

func TestProxyBlocksPendingToolBeforeUpstream(t *testing.T) {
	loaded, err := policy.Parse([]byte(policy.DefaultPolicy))
	if err != nil {
		t.Fatal(err)
	}
	dataDir := t.TempDir()
	eng := &engine.Engine{
		Policy: loaded, Approvals: approval.New(dataDir, time.Minute), Ledger: audit.New(dataDir),
	}
	proxy := &Proxy{Engine: eng, Workspace: t.TempDir()}
	input := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"README.md"}}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"create_issue","arguments":{"title":"side effect"}}}`,
	}, "\n") + "\n"
	var output bytes.Buffer
	var diagnostics bytes.Buffer
	t.Setenv("GO_WANT_MCP_HELPER", "1")
	err = proxy.Run(context.Background(), strings.NewReader(input), &output, &diagnostics, os.Args[0], "-test.run=TestMCPHelperProcess")
	if err != nil {
		t.Fatalf("proxy: %v; diagnostics=%s", err, diagnostics.String())
	}
	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("output lines=%d: %s", len(lines), output.String())
	}
	if !strings.Contains(output.String(), `"id":1`) || !strings.Contains(output.String(), `"ok":true`) {
		t.Fatalf("safe tool was not forwarded: %s", output.String())
	}
	if !strings.Contains(output.String(), `"id":2`) || !strings.Contains(output.String(), `"firewall_decision":"ask"`) {
		t.Fatalf("write tool was not held for approval: %s", output.String())
	}
	if strings.Contains(output.String(), `"upstream":"create_issue"`) {
		t.Fatalf("pending tool reached upstream: %s", output.String())
	}
	events, err := audit.New(dataDir).Events(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 3 {
		t.Fatalf("events=%d, want allow decision + completion + ask decision", len(events))
	}
}

func TestMCPHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_MCP_HELPER") != "1" {
		return
	}
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		var message struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params struct {
				Name string `json:"name"`
			} `json:"params"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &message); err != nil {
			os.Exit(2)
		}
		fmt.Printf(`{"jsonrpc":"2.0","id":%s,"result":{"ok":true,"upstream":%q}}`+"\n", message.ID, message.Params.Name)
	}
	os.Exit(0)
}

func TestDecodeFrameRejectsTrailingValue(t *testing.T) {
	var message rpcMessage
	if err := decodeFrame([]byte(`{"jsonrpc":"2.0"} {"jsonrpc":"2.0"}`), &message); err == nil {
		t.Fatal("expected trailing JSON value to be rejected")
	}
}

func FuzzDecodeFrame(f *testing.F) {
	f.Add([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	f.Add([]byte(`[{"jsonrpc":"2.0"}]`))
	f.Add([]byte(`{"jsonrpc":"2.0"} {"id":2}`))
	f.Fuzz(func(t *testing.T, frame []byte) {
		var message rpcMessage
		_ = decodeFrame(frame, &message)
	})
}
