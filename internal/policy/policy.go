package policy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/YuYigeng/agent-firewall/internal/action"
	"github.com/bmatcuk/doublestar/v4"
	"gopkg.in/yaml.v3"
)

const Schema = "afw.policy/v1alpha1"

type DecisionValue string

const (
	DecisionAllow DecisionValue = "allow"
	DecisionAsk   DecisionValue = "ask"
	DecisionDeny  DecisionValue = "deny"
)

var decisionRank = map[DecisionValue]int{
	DecisionAllow: 0,
	DecisionAsk:   1,
	DecisionDeny:  2,
}

type Defaults struct {
	Low      DecisionValue `yaml:"low" json:"low"`
	Medium   DecisionValue `yaml:"medium" json:"medium"`
	High     DecisionValue `yaml:"high" json:"high"`
	Critical DecisionValue `yaml:"critical" json:"critical"`
	OnError  DecisionValue `yaml:"on_error" json:"on_error"`
}

type Redaction struct {
	Environment []string `yaml:"environment,omitempty" json:"environment,omitempty"`
	Paths       []string `yaml:"paths,omitempty" json:"paths,omitempty"`
}

type Match struct {
	Sources          []string      `yaml:"sources,omitempty" json:"sources,omitempty"`
	Kinds            []action.Kind `yaml:"kinds,omitempty" json:"kinds,omitempty"`
	Operations       []string      `yaml:"operations,omitempty" json:"operations,omitempty"`
	ToolGlobs        []string      `yaml:"tool_globs,omitempty" json:"tool_globs,omitempty"`
	PathGlobs        []string      `yaml:"path_globs,omitempty" json:"path_globs,omitempty"`
	ExcludePathGlobs []string      `yaml:"exclude_path_globs,omitempty" json:"exclude_path_globs,omitempty"`
	HostGlobs        []string      `yaml:"host_globs,omitempty" json:"host_globs,omitempty"`
	Signals          []string      `yaml:"signals,omitempty" json:"signals,omitempty"`
	RiskAtLeast      action.Risk   `yaml:"risk_at_least,omitempty" json:"risk_at_least,omitempty"`
	PathScope        string        `yaml:"path_scope,omitempty" json:"path_scope,omitempty"`
	CommandRegex     string        `yaml:"command_regex,omitempty" json:"command_regex,omitempty"`
	ArgumentRegex    string        `yaml:"argument_regex,omitempty" json:"argument_regex,omitempty"`

	commandRE  *regexp.Regexp `yaml:"-" json:"-"`
	argumentRE *regexp.Regexp `yaml:"-" json:"-"`
}

type Rule struct {
	ID          string        `yaml:"id" json:"id"`
	Description string        `yaml:"description,omitempty" json:"description,omitempty"`
	Priority    int           `yaml:"priority" json:"priority"`
	Decision    DecisionValue `yaml:"decision" json:"decision"`
	Match       Match         `yaml:"match" json:"match"`
}

type Policy struct {
	Version   string    `yaml:"version" json:"version"`
	Name      string    `yaml:"name" json:"name"`
	Defaults  Defaults  `yaml:"defaults" json:"defaults"`
	Redaction Redaction `yaml:"redaction,omitempty" json:"redaction,omitempty"`
	Rules     []Rule    `yaml:"rules,omitempty" json:"rules,omitempty"`
	Digest    string    `yaml:"-" json:"-"`
}

type Trace struct {
	RuleID   string `json:"rule_id"`
	Priority int    `json:"priority"`
	Matched  bool   `json:"matched"`
	Detail   string `json:"detail,omitempty"`
}

type Decision struct {
	Schema            string        `json:"schema"`
	Decision          DecisionValue `json:"decision"`
	Risk              action.Risk   `json:"risk"`
	RuleID            string        `json:"rule_id"`
	Reason            string        `json:"reason"`
	ActionFingerprint string        `json:"action_fingerprint"`
	ApprovalID        string        `json:"approval_id,omitempty"`
	PolicyDigest      string        `json:"policy_digest"`
	Trace             []Trace       `json:"trace,omitempty"`
}

func Load(path string) (*Policy, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read policy: %w", err)
	}
	return Parse(raw)
}

func Parse(raw []byte) (*Policy, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	decoder.KnownFields(true)
	var policy Policy
	if err := decoder.Decode(&policy); err != nil {
		return nil, fmt.Errorf("decode policy: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return nil, errors.New("decode policy: multiple YAML documents are not supported")
		}
		return nil, fmt.Errorf("decode policy trailing content: %w", err)
	}
	if err := policy.compile(); err != nil {
		return nil, err
	}
	canonical, err := json.Marshal(policy)
	if err != nil {
		return nil, fmt.Errorf("canonicalize policy: %w", err)
	}
	sum := sha256.Sum256(canonical)
	policy.Digest = "sha256:" + hex.EncodeToString(sum[:])
	return &policy, nil
}

func (p *Policy) compile() error {
	if p.Version != Schema {
		return fmt.Errorf("unsupported policy schema %q", p.Version)
	}
	if strings.TrimSpace(p.Name) == "" {
		return errors.New("policy name is required")
	}
	for label, value := range map[string]DecisionValue{
		"defaults.low": p.Defaults.Low, "defaults.medium": p.Defaults.Medium,
		"defaults.high": p.Defaults.High, "defaults.critical": p.Defaults.Critical,
		"defaults.on_error": p.Defaults.OnError,
	} {
		if err := validateDecision(value); err != nil {
			return fmt.Errorf("%s: %w", label, err)
		}
	}
	ids := make(map[string]struct{}, len(p.Rules))
	for index := range p.Rules {
		rule := &p.Rules[index]
		if strings.TrimSpace(rule.ID) == "" {
			return fmt.Errorf("rules[%d].id is required", index)
		}
		if _, exists := ids[rule.ID]; exists {
			return fmt.Errorf("duplicate rule id %q", rule.ID)
		}
		ids[rule.ID] = struct{}{}
		if err := validateDecision(rule.Decision); err != nil {
			return fmt.Errorf("rule %q: %w", rule.ID, err)
		}
		if rule.Match.RiskAtLeast != "" && action.RiskRank(rule.Match.RiskAtLeast) == 0 && rule.Match.RiskAtLeast != action.RiskLow {
			return fmt.Errorf("rule %q: invalid risk_at_least %q", rule.ID, rule.Match.RiskAtLeast)
		}
		switch rule.Match.PathScope {
		case "", "any", "workspace", "outside-workspace":
		default:
			return fmt.Errorf("rule %q: invalid path_scope %q", rule.ID, rule.Match.PathScope)
		}
		if rule.Match.CommandRegex != "" {
			compiled, err := regexp.Compile(rule.Match.CommandRegex)
			if err != nil {
				return fmt.Errorf("rule %q command_regex: %w", rule.ID, err)
			}
			rule.Match.commandRE = compiled
		}
		if rule.Match.ArgumentRegex != "" {
			compiled, err := regexp.Compile(rule.Match.ArgumentRegex)
			if err != nil {
				return fmt.Errorf("rule %q argument_regex: %w", rule.ID, err)
			}
			rule.Match.argumentRE = compiled
		}
		globs := make([]string, 0, len(rule.Match.ToolGlobs)+len(rule.Match.PathGlobs)+len(rule.Match.ExcludePathGlobs)+len(rule.Match.HostGlobs))
		globs = append(globs, rule.Match.ToolGlobs...)
		globs = append(globs, rule.Match.PathGlobs...)
		globs = append(globs, rule.Match.ExcludePathGlobs...)
		globs = append(globs, rule.Match.HostGlobs...)
		for _, glob := range globs {
			if _, err := doublestar.Match(glob, "validation/path"); err != nil {
				return fmt.Errorf("rule %q invalid glob %q: %w", rule.ID, glob, err)
			}
		}
	}
	return nil
}

func validateDecision(value DecisionValue) error {
	if _, ok := decisionRank[value]; !ok {
		return fmt.Errorf("invalid decision %q", value)
	}
	return nil
}

func (p *Policy) Evaluate(a action.Action) (Decision, error) {
	a.Normalize()
	if err := a.Validate(); err != nil {
		return Decision{}, err
	}
	fingerprint, err := a.Fingerprint()
	if err != nil {
		return Decision{}, err
	}
	traces := make([]Trace, 0, len(p.Rules))
	matched := make([]Rule, 0)
	for _, rule := range p.Rules {
		ok, detail := matches(rule.Match, a)
		traces = append(traces, Trace{RuleID: rule.ID, Priority: rule.Priority, Matched: ok, Detail: detail})
		if ok {
			matched = append(matched, rule)
		}
	}
	if len(matched) == 0 {
		value := p.defaultFor(a.Risk)
		return Decision{
			Schema: "afw.decision/v1alpha1", Decision: value, Risk: a.Risk,
			RuleID: "default-" + string(a.Risk), Reason: "Policy default for " + string(a.Risk) + " risk",
			ActionFingerprint: fingerprint, PolicyDigest: p.Digest, Trace: traces,
		}, nil
	}
	sort.SliceStable(matched, func(i, j int) bool {
		if matched[i].Priority != matched[j].Priority {
			return matched[i].Priority > matched[j].Priority
		}
		if decisionRank[matched[i].Decision] != decisionRank[matched[j].Decision] {
			return decisionRank[matched[i].Decision] > decisionRank[matched[j].Decision]
		}
		return matched[i].ID < matched[j].ID
	})
	selected := matched[0]
	reason := selected.Description
	if reason == "" {
		reason = fmt.Sprintf("Matched policy rule %s", selected.ID)
	}
	return Decision{
		Schema: "afw.decision/v1alpha1", Decision: selected.Decision, Risk: a.Risk,
		RuleID: selected.ID, Reason: reason, ActionFingerprint: fingerprint,
		PolicyDigest: p.Digest, Trace: traces,
	}, nil
}

func (p *Policy) defaultFor(risk action.Risk) DecisionValue {
	switch risk {
	case action.RiskCritical:
		return p.Defaults.Critical
	case action.RiskHigh:
		return p.Defaults.High
	case action.RiskMedium:
		return p.Defaults.Medium
	default:
		return p.Defaults.Low
	}
}

func matches(match Match, a action.Action) (bool, string) {
	if len(match.Sources) > 0 && !containsFold(match.Sources, a.Source) {
		return false, "source"
	}
	if len(match.Kinds) > 0 && !containsKind(match.Kinds, a.Kind) {
		return false, "kind"
	}
	if len(match.Operations) > 0 && !containsFold(match.Operations, a.Operation) {
		return false, "operation"
	}
	toolName := attributeString(a.Attributes, "tool_name")
	if len(match.ToolGlobs) > 0 && !matchesAnyGlob(match.ToolGlobs, toolName) {
		return false, "tool_globs"
	}
	paths := attributeStrings(a.Attributes, "paths")
	if len(paths) == 0 && a.Subject != "" && (a.Kind == action.KindFileRead || a.Kind == action.KindFileWrite) {
		paths = []string{a.Subject}
	}
	if len(match.ExcludePathGlobs) > 0 && matchesAnyPath(match.ExcludePathGlobs, paths) {
		return false, "excluded_path"
	}
	if len(match.PathGlobs) > 0 && !matchesAnyPath(match.PathGlobs, paths) {
		return false, "path_globs"
	}
	hosts := attributeStrings(a.Attributes, "hosts")
	if len(match.HostGlobs) > 0 && !matchesAnyGlobForValues(match.HostGlobs, hosts) {
		return false, "host_globs"
	}
	for _, signal := range match.Signals {
		if !a.HasSignal(signal) {
			return false, "signal:" + signal
		}
	}
	if match.RiskAtLeast != "" && action.RiskRank(a.Risk) < action.RiskRank(match.RiskAtLeast) {
		return false, "risk_at_least"
	}
	if match.PathScope != "" && match.PathScope != "any" && attributeString(a.Attributes, "path_scope") != match.PathScope {
		return false, "path_scope"
	}
	if match.commandRE != nil && !match.commandRE.MatchString(attributeString(a.Attributes, "command")) {
		return false, "command_regex"
	}
	if match.argumentRE != nil {
		raw, _ := json.Marshal(a.Attributes["arguments"])
		if !match.argumentRE.Match(raw) {
			return false, "argument_regex"
		}
	}
	return true, "matched"
}

func containsFold(values []string, want string) bool {
	for _, value := range values {
		if strings.EqualFold(value, want) {
			return true
		}
	}
	return false
}

func containsKind(values []action.Kind, want action.Kind) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func attributeString(attributes map[string]any, key string) string {
	value, _ := attributes[key].(string)
	return value
}

func attributeStrings(attributes map[string]any, key string) []string {
	switch values := attributes[key].(type) {
	case []string:
		return values
	case []any:
		out := make([]string, 0, len(values))
		for _, value := range values {
			if text, ok := value.(string); ok {
				out = append(out, text)
			}
		}
		return out
	case string:
		if values != "" {
			return []string{values}
		}
	}
	return nil
}

func matchesAnyPath(patterns, values []string) bool {
	normalized := make([]string, 0, len(values)*2)
	for _, value := range values {
		value = filepath.ToSlash(value)
		normalized = append(normalized, value, strings.TrimPrefix(value, "/"))
	}
	return matchesAnyGlobForValues(patterns, normalized)
}

func matchesAnyGlobForValues(patterns, values []string) bool {
	for _, value := range values {
		if matchesAnyGlob(patterns, value) {
			return true
		}
	}
	return false
}

func matchesAnyGlob(patterns []string, value string) bool {
	for _, pattern := range patterns {
		ok, err := doublestar.Match(strings.ToLower(pattern), strings.ToLower(filepath.ToSlash(value)))
		if err == nil && ok {
			return true
		}
	}
	return false
}

const DefaultPolicy = `version: afw.policy/v1alpha1
name: balanced-local

defaults:
  low: allow
  medium: ask
  high: ask
  critical: deny
  on_error: deny

redaction:
  environment:
    - '*_TOKEN'
    - '*_SECRET'
    - '*_PASSWORD'
    - '*_KEY'
  paths:
    - '**/.env*'
    - '**/.ssh/**'
    - '**/.aws/credentials'

rules:
  - id: deny-destructive-root
    description: Destructive root or device operation blocked
    priority: 1000
    decision: deny
    match:
      kinds: [shell]
      signals: [destructive-root]

  - id: deny-reverse-shell
    description: Reverse shell behavior blocked
    priority: 1000
    decision: deny
    match:
      kinds: [shell]
      signals: [reverse-shell]

  - id: deny-cloud-metadata
    description: Cloud metadata endpoint access blocked
    priority: 1000
    decision: deny
    match:
      signals: [cloud-metadata]

  - id: deny-potential-exfiltration
    description: Network action combined with a secret reference blocked
    priority: 950
    decision: deny
    match:
      signals: [potential-exfiltration]

  - id: ask-outside-workspace
    description: Action targets a path outside the active workspace
    priority: 800
    decision: ask
    match:
      signals: [outside-workspace]

  - id: ask-sensitive-path
    description: Action touches a sensitive path
    priority: 800
    decision: ask
    match:
      signals: [sensitive-path]

  - id: ask-persistence
    description: Action can create persistent execution
    priority: 750
    decision: ask
    match:
      signals: [persistence]

  - id: ask-agent-config
    description: Action changes agent security or behavior configuration
    priority: 750
    decision: ask
    match:
      signals: [agent-config]

  - id: ask-privilege
    description: Privilege-changing action requires review
    priority: 700
    decision: ask
    match:
      signals: [privilege]

  - id: ask-network-write
    description: Outbound state-changing network action requires review
    priority: 650
    decision: ask
    match:
      signals: [network-write]

  - id: ask-destructive
    description: Destructive action requires review
    priority: 650
    decision: ask
    match:
      signals: [destructive]

  - id: ask-protected-git-write
    description: Protected Git history or branch action requires review
    priority: 650
    decision: ask
    match:
      signals: [protected-git-write]

  - id: ask-state-changing-tool
    description: State-changing tool call requires review
    priority: 600
    decision: ask
    match:
      signals: [state-changing-tool]

  - id: ask-package-install
    description: Package installation executes third-party supply-chain code
    priority: 550
    decision: ask
    match:
      signals: [package-install]

  - id: ask-dynamic-shell
    description: Dynamic shell execution is difficult to inspect safely
    priority: 550
    decision: ask
    match:
      signals: [dynamic-shell]

  - id: allow-workspace-writes
    description: Ordinary file write remains inside the active workspace
    priority: 100
    decision: allow
    match:
      kinds: [file_write]
      path_scope: workspace
      exclude_path_globs:
        - '**/.env*'
        - '**/.git/hooks/**'
        - '**/.codex/**'
        - '**/.claude/**'
        - '**/.openclaw/**'
`

func WriteDefault(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = file.WriteString(DefaultPolicy)
	return err
}
