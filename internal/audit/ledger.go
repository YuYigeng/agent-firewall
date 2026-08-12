package audit

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/YuYigeng/agent-firewall/internal/action"
	"github.com/YuYigeng/agent-firewall/internal/policy"
	"github.com/YuYigeng/agent-firewall/internal/redact"
	"github.com/gofrs/flock"
)

type Event struct {
	Sequence          uint64           `json:"sequence"`
	ID                string           `json:"id"`
	Timestamp         time.Time        `json:"timestamp"`
	Type              string           `json:"type"`
	Observer          string           `json:"observer"`
	ActionFingerprint string           `json:"action_fingerprint,omitempty"`
	Action            *action.Action   `json:"action,omitempty"`
	Decision          *DecisionSummary `json:"decision,omitempty"`
	Metadata          map[string]any   `json:"metadata,omitempty"`
	Redactions        map[string]int   `json:"redactions,omitempty"`
	PreviousHash      string           `json:"previous_hash"`
	Hash              string           `json:"hash"`
}

type DecisionSummary struct {
	Value        policy.DecisionValue `json:"value"`
	Risk         action.Risk          `json:"risk"`
	RuleID       string               `json:"rule_id"`
	Reason       string               `json:"reason"`
	ApprovalID   string               `json:"approval_id,omitempty"`
	PolicyDigest string               `json:"policy_digest"`
}

type Head struct {
	Sequence uint64 `json:"sequence"`
	Hash     string `json:"hash"`
}

type VerifyReport struct {
	Valid        bool   `json:"valid"`
	Events       uint64 `json:"events"`
	Head         string `json:"head,omitempty"`
	ExpectedHead string `json:"expected_head,omitempty"`
	Error        string `json:"error,omitempty"`
}

type Ledger struct {
	dir string
}

func New(dataDir string) *Ledger {
	return &Ledger{dir: filepath.Join(dataDir, "audit")}
}

func (l *Ledger) AppendDecision(ctx context.Context, observer string, a action.Action, decision policy.Decision) (Event, error) {
	safeAction, report := redact.Action(a)
	reason := redact.SafeReason(decision.RuleID, decision.Reason)
	event := Event{
		Timestamp:         time.Now().UTC(),
		Type:              "decision",
		Observer:          observer,
		ActionFingerprint: decision.ActionFingerprint,
		Action:            &safeAction,
		Decision: &DecisionSummary{
			Value: decision.Decision, Risk: decision.Risk, RuleID: decision.RuleID,
			Reason: reason, ApprovalID: decision.ApprovalID, PolicyDigest: decision.PolicyDigest,
		},
		Redactions: report,
	}
	return l.Append(ctx, event)
}

func (l *Ledger) AppendCompletion(ctx context.Context, observer string, a action.Action, metadata map[string]any) (Event, error) {
	safeAction, report := redact.Action(a)
	metadataReport := redact.Report{}
	safeMetadata, _ := redact.Value(metadata, metadataReport).(map[string]any)
	for category, count := range metadataReport {
		report[category] += count
	}
	fingerprint, err := a.Fingerprint()
	if err != nil {
		return Event{}, err
	}
	return l.Append(ctx, Event{
		Timestamp: time.Now().UTC(), Type: "completion", Observer: observer,
		ActionFingerprint: fingerprint, Action: &safeAction, Metadata: safeMetadata, Redactions: report,
	})
}

func (l *Ledger) Append(ctx context.Context, event Event) (Event, error) {
	if err := os.MkdirAll(l.dir, 0o700); err != nil {
		return Event{}, fmt.Errorf("create audit directory: %w", err)
	}
	lock := flock.New(filepath.Join(l.dir, "ledger.lock"))
	locked, err := lock.TryLockContext(ctx, 25*time.Millisecond)
	if err != nil {
		return Event{}, fmt.Errorf("lock audit ledger: %w", err)
	}
	if !locked {
		return Event{}, errors.New("audit ledger lock timeout")
	}
	defer lock.Unlock()

	head, err := l.readHead()
	if err != nil {
		return Event{}, err
	}
	event.Sequence = head.Sequence + 1
	event.PreviousHash = head.Hash
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}
	if event.ID == "" {
		event.ID, err = newID()
		if err != nil {
			return Event{}, err
		}
	}
	event.Hash, err = eventHash(event)
	if err != nil {
		return Event{}, err
	}
	raw, err := json.Marshal(event)
	if err != nil {
		return Event{}, err
	}
	path := filepath.Join(l.dir, "events.jsonl")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return Event{}, fmt.Errorf("open audit ledger: %w", err)
	}
	if _, err := file.Write(append(raw, '\n')); err != nil {
		file.Close()
		return Event{}, fmt.Errorf("append audit event: %w", err)
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return Event{}, fmt.Errorf("sync audit event: %w", err)
	}
	if err := file.Close(); err != nil {
		return Event{}, err
	}
	if err := l.writeHead(Head{Sequence: event.Sequence, Hash: event.Hash}); err != nil {
		return Event{}, err
	}
	return event, nil
}

func (l *Ledger) Verify(trustedHead string) VerifyReport {
	path := filepath.Join(l.dir, "events.jsonl")
	file, err := os.Open(path)
	if os.IsNotExist(err) {
		if trustedHead == "" {
			return VerifyReport{Valid: true}
		}
		return VerifyReport{Valid: false, ExpectedHead: trustedHead, Error: "ledger is empty"}
	}
	if err != nil {
		return VerifyReport{Valid: false, Error: err.Error()}
	}
	defer file.Close()

	report := VerifyReport{Valid: true, ExpectedHead: trustedHead}
	previous := ""
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 16*1024*1024)
	for scanner.Scan() {
		var event Event
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			return VerifyReport{Valid: false, Events: report.Events, Head: previous, ExpectedHead: trustedHead, Error: fmt.Sprintf("event %d decode: %v", report.Events+1, err)}
		}
		expectedSequence := report.Events + 1
		if event.Sequence != expectedSequence {
			return VerifyReport{Valid: false, Events: report.Events, Head: previous, ExpectedHead: trustedHead, Error: fmt.Sprintf("event sequence %d, expected %d", event.Sequence, expectedSequence)}
		}
		if event.PreviousHash != previous {
			return VerifyReport{Valid: false, Events: report.Events, Head: previous, ExpectedHead: trustedHead, Error: fmt.Sprintf("event %d previous hash mismatch", event.Sequence)}
		}
		hash, err := eventHash(event)
		if err != nil || hash != event.Hash {
			return VerifyReport{Valid: false, Events: report.Events, Head: previous, ExpectedHead: trustedHead, Error: fmt.Sprintf("event %d hash mismatch", event.Sequence)}
		}
		previous = event.Hash
		report.Events++
	}
	if err := scanner.Err(); err != nil {
		return VerifyReport{Valid: false, Events: report.Events, Head: previous, ExpectedHead: trustedHead, Error: err.Error()}
	}
	report.Head = previous
	if trustedHead == "" {
		if head, err := l.readHead(); err == nil {
			report.ExpectedHead = head.Hash
		} else {
			report.Valid = false
			report.Error = err.Error()
			return report
		}
	}
	if report.ExpectedHead != "" && report.ExpectedHead != previous {
		report.Valid = false
		report.Error = "trusted head mismatch; ledger may be truncated or replaced"
	}
	return report
}

func (l *Ledger) Events(limit int) ([]Event, error) {
	path := filepath.Join(l.dir, "events.jsonl")
	file, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var events []Event
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 16*1024*1024)
	for scanner.Scan() {
		var event Event
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if limit > 0 && len(events) > limit {
		events = events[len(events)-limit:]
	}
	sort.SliceStable(events, func(i, j int) bool { return events[i].Sequence < events[j].Sequence })
	return events, nil
}

func (l *Ledger) Export(writer io.Writer) error {
	file, err := os.Open(filepath.Join(l.dir, "events.jsonl"))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = io.Copy(writer, file)
	return err
}

func (l *Ledger) readHead() (Head, error) {
	raw, err := os.ReadFile(filepath.Join(l.dir, "head.json"))
	if os.IsNotExist(err) {
		return Head{}, nil
	}
	if err != nil {
		return Head{}, fmt.Errorf("read audit head: %w", err)
	}
	var head Head
	if err := json.Unmarshal(raw, &head); err != nil {
		return Head{}, fmt.Errorf("decode audit head: %w", err)
	}
	return head, nil
}

func (l *Ledger) writeHead(head Head) error {
	raw, err := json.Marshal(head)
	if err != nil {
		return err
	}
	temp, err := os.CreateTemp(l.dir, "head-*.tmp")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if err := temp.Chmod(0o600); err != nil {
		temp.Close()
		return err
	}
	if _, err := temp.Write(raw); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tempPath, filepath.Join(l.dir, "head.json")); err != nil {
		return fmt.Errorf("replace audit head: %w", err)
	}
	return nil
}

func eventHash(event Event) (string, error) {
	event.Hash = ""
	raw, err := json.Marshal(event)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func newID() (string, error) {
	raw := make([]byte, 10)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return "evt_" + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)), nil
}
