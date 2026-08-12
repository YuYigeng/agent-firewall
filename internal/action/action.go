package action

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

const Schema = "afw.action/v1alpha1"

type Kind string

const (
	KindShell     Kind = "shell"
	KindFileRead  Kind = "file_read"
	KindFileWrite Kind = "file_write"
	KindNetwork   Kind = "network"
	KindSecret    Kind = "secret"
	KindTool      Kind = "tool"
)

type Risk string

const (
	RiskLow      Risk = "low"
	RiskMedium   Risk = "medium"
	RiskHigh     Risk = "high"
	RiskCritical Risk = "critical"
)

var riskRanks = map[Risk]int{
	RiskLow:      0,
	RiskMedium:   1,
	RiskHigh:     2,
	RiskCritical: 3,
}

type Action struct {
	Schema     string         `json:"schema" yaml:"schema"`
	ID         string         `json:"id,omitempty" yaml:"id,omitempty"`
	Timestamp  time.Time      `json:"timestamp" yaml:"timestamp"`
	Source     string         `json:"source" yaml:"source"`
	SessionID  string         `json:"session_id,omitempty" yaml:"session_id,omitempty"`
	Workspace  string         `json:"workspace" yaml:"workspace"`
	Kind       Kind           `json:"kind" yaml:"kind"`
	Operation  string         `json:"operation" yaml:"operation"`
	Subject    string         `json:"subject,omitempty" yaml:"subject,omitempty"`
	Attributes map[string]any `json:"attributes,omitempty" yaml:"attributes,omitempty"`
	Signals    []string       `json:"signals,omitempty" yaml:"signals,omitempty"`
	Risk       Risk           `json:"risk" yaml:"risk"`
}

func (a *Action) Normalize() {
	if a.Schema == "" {
		a.Schema = Schema
	}
	if a.Timestamp.IsZero() {
		a.Timestamp = time.Now().UTC()
	} else {
		a.Timestamp = a.Timestamp.UTC()
	}
	a.Source = strings.TrimSpace(strings.ToLower(a.Source))
	a.Operation = strings.TrimSpace(a.Operation)
	a.Subject = strings.TrimSpace(a.Subject)
	if a.Attributes == nil {
		a.Attributes = map[string]any{}
	}
	seen := make(map[string]struct{}, len(a.Signals))
	clean := make([]string, 0, len(a.Signals))
	for _, signal := range a.Signals {
		signal = strings.TrimSpace(strings.ToLower(signal))
		if signal == "" {
			continue
		}
		if _, ok := seen[signal]; ok {
			continue
		}
		seen[signal] = struct{}{}
		clean = append(clean, signal)
	}
	sort.Strings(clean)
	a.Signals = clean
	if _, ok := riskRanks[a.Risk]; !ok {
		a.Risk = RiskLow
	}
}

func (a Action) Validate() error {
	if a.Schema != Schema {
		return fmt.Errorf("unsupported action schema %q", a.Schema)
	}
	if a.Source == "" {
		return errors.New("action source is required")
	}
	if a.Workspace == "" {
		return errors.New("action workspace is required")
	}
	if a.Operation == "" {
		return errors.New("action operation is required")
	}
	switch a.Kind {
	case KindShell, KindFileRead, KindFileWrite, KindNetwork, KindSecret, KindTool:
	default:
		return fmt.Errorf("unsupported action kind %q", a.Kind)
	}
	if _, ok := riskRanks[a.Risk]; !ok {
		return fmt.Errorf("unsupported risk %q", a.Risk)
	}
	return nil
}

func RiskRank(risk Risk) int {
	return riskRanks[risk]
}

func MaxRisk(left, right Risk) Risk {
	if RiskRank(right) > RiskRank(left) {
		return right
	}
	return left
}

func (a Action) HasSignal(want string) bool {
	want = strings.ToLower(want)
	for _, signal := range a.Signals {
		if signal == want {
			return true
		}
	}
	return false
}

func (a Action) Fingerprint() (string, error) {
	stable := struct {
		Schema     string         `json:"schema"`
		Source     string         `json:"source"`
		Workspace  string         `json:"workspace"`
		Kind       Kind           `json:"kind"`
		Operation  string         `json:"operation"`
		Subject    string         `json:"subject,omitempty"`
		Attributes map[string]any `json:"attributes,omitempty"`
		Signals    []string       `json:"signals,omitempty"`
		Risk       Risk           `json:"risk"`
	}{
		Schema:     a.Schema,
		Source:     a.Source,
		Workspace:  a.Workspace,
		Kind:       a.Kind,
		Operation:  a.Operation,
		Subject:    a.Subject,
		Attributes: a.Attributes,
		Signals:    a.Signals,
		Risk:       a.Risk,
	}
	raw, err := json.Marshal(stable)
	if err != nil {
		return "", fmt.Errorf("marshal action fingerprint: %w", err)
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
