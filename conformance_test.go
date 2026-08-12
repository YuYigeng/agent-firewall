package agentfirewall_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/YuYigeng/agent-firewall/internal/analyze"
	"github.com/YuYigeng/agent-firewall/internal/policy"
	"gopkg.in/yaml.v3"
)

type corpus struct {
	Version string `yaml:"version"`
	Cases   []struct {
		ID     string         `yaml:"id"`
		Tool   string         `yaml:"tool"`
		Input  map[string]any `yaml:"input"`
		Expect struct {
			Decision policy.DecisionValue `yaml:"decision"`
			Rule     string               `yaml:"rule"`
		} `yaml:"expect"`
	} `yaml:"cases"`
}

func TestActionCorpusAcrossHosts(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "action-corpus.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var fixtures corpus
	if err := yaml.Unmarshal(raw, &fixtures); err != nil {
		t.Fatal(err)
	}
	if fixtures.Version != "afw.corpus/v1alpha1" {
		t.Fatalf("unexpected corpus version %q", fixtures.Version)
	}
	loaded, err := policy.Parse([]byte(policy.DefaultPolicy))
	if err != nil {
		t.Fatal(err)
	}
	workspace := t.TempDir()
	for _, fixture := range fixtures.Cases {
		for _, source := range []string{"codex", "claude", "openclaw"} {
			t.Run(fixture.ID+"/"+source, func(t *testing.T) {
				event, err := analyze.Normalize(analyze.Input{
					Source: source, Workspace: workspace, ToolName: fixture.Tool, ToolInput: fixture.Input,
				})
				if err != nil {
					t.Fatal(err)
				}
				decision, err := loaded.Evaluate(event)
				if err != nil {
					t.Fatal(err)
				}
				if decision.Decision != fixture.Expect.Decision || decision.RuleID != fixture.Expect.Rule {
					t.Fatalf("got %s/%s, want %s/%s; risk=%s signals=%v", decision.Decision, decision.RuleID, fixture.Expect.Decision, fixture.Expect.Rule, event.Risk, event.Signals)
				}
			})
		}
	}
}
