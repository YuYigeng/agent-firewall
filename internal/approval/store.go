package approval

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/gofrs/flock"
)

type Status string

const (
	StatusPending  Status = "pending"
	StatusApproved Status = "approved"
	StatusDenied   Status = "denied"
	StatusConsumed Status = "consumed"
	StatusExpired  Status = "expired"
)

type Request struct {
	ID                string    `json:"id"`
	ActionFingerprint string    `json:"action_fingerprint"`
	Workspace         string    `json:"workspace"`
	PolicyDigest      string    `json:"policy_digest"`
	RuleID            string    `json:"rule_id"`
	Reason            string    `json:"reason"`
	Risk              string    `json:"risk"`
	Status            Status    `json:"status"`
	CreatedAt         time.Time `json:"created_at"`
	ExpiresAt         time.Time `json:"expires_at"`
	ResolvedAt        time.Time `json:"resolved_at,omitempty"`
	RemainingUses     int       `json:"remaining_uses"`
}

type diskState struct {
	Requests []Request `json:"requests"`
}

type Store struct {
	dir string
	ttl time.Duration
}

func New(dataDir string, ttl time.Duration) *Store {
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	return &Store{dir: filepath.Join(dataDir, "approvals"), ttl: ttl}
}

func (s *Store) Create(ctx context.Context, request Request) (Request, error) {
	var result Request
	err := s.withState(ctx, true, func(state *diskState) error {
		now := time.Now().UTC()
		cleanup(state, now)
		for _, existing := range state.Requests {
			if (existing.Status == StatusPending || existing.Status == StatusDenied) && existing.ExpiresAt.After(now) && sameBinding(existing, request) {
				result = existing
				return nil
			}
		}
		id, err := newID()
		if err != nil {
			return err
		}
		request.ID = id
		request.Status = StatusPending
		request.CreatedAt = now
		request.ExpiresAt = now.Add(s.ttl)
		request.RemainingUses = 1
		state.Requests = append(state.Requests, request)
		result = request
		return nil
	})
	return result, err
}

func (s *Store) Resolve(ctx context.Context, id string, approve bool) (Request, error) {
	var result Request
	err := s.withState(ctx, true, func(state *diskState) error {
		now := time.Now().UTC()
		cleanup(state, now)
		for index := range state.Requests {
			request := &state.Requests[index]
			if request.ID != id {
				continue
			}
			if request.Status != StatusPending {
				return fmt.Errorf("approval %s is %s", id, request.Status)
			}
			if approve {
				request.Status = StatusApproved
				request.ExpiresAt = now.Add(s.ttl)
			} else {
				request.Status = StatusDenied
			}
			request.ResolvedAt = now
			result = *request
			return nil
		}
		return fmt.Errorf("approval %s not found", id)
	})
	return result, err
}

func (s *Store) Consume(ctx context.Context, fingerprint, workspace, policyDigest string) (*Request, error) {
	var result *Request
	err := s.withState(ctx, true, func(state *diskState) error {
		now := time.Now().UTC()
		cleanup(state, now)
		for index := range state.Requests {
			request := &state.Requests[index]
			if request.Status != StatusApproved || request.RemainingUses <= 0 {
				continue
			}
			if request.ActionFingerprint != fingerprint || request.Workspace != workspace || request.PolicyDigest != policyDigest {
				continue
			}
			request.RemainingUses--
			request.Status = StatusConsumed
			request.ResolvedAt = now
			copy := *request
			result = &copy
			return nil
		}
		return nil
	})
	return result, err
}

func (s *Store) List(ctx context.Context, includeResolved bool) ([]Request, error) {
	var requests []Request
	err := s.withState(ctx, false, func(state *diskState) error {
		now := time.Now().UTC()
		cleanup(state, now)
		for _, request := range state.Requests {
			if includeResolved || request.Status == StatusPending || request.Status == StatusApproved {
				requests = append(requests, request)
			}
		}
		sort.Slice(requests, func(i, j int) bool { return requests[i].CreatedAt.After(requests[j].CreatedAt) })
		return nil
	})
	return requests, err
}

func (s *Store) withState(ctx context.Context, write bool, fn func(*diskState) error) error {
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return fmt.Errorf("create approval directory: %w", err)
	}
	lock := flock.New(filepath.Join(s.dir, "store.lock"))
	locked, err := lock.TryLockContext(ctx, 25*time.Millisecond)
	if err != nil {
		return fmt.Errorf("lock approval store: %w", err)
	}
	if !locked {
		return errors.New("approval store lock timeout")
	}
	defer lock.Unlock()

	path := filepath.Join(s.dir, "approvals.json")
	state := diskState{}
	if raw, err := os.ReadFile(path); err == nil {
		if err := json.Unmarshal(raw, &state); err != nil {
			return fmt.Errorf("decode approval store: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("read approval store: %w", err)
	}
	if err := fn(&state); err != nil {
		return err
	}
	if !write {
		return nil
	}
	raw, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	temp, err := os.CreateTemp(s.dir, "approvals-*.tmp")
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
	if err := os.Rename(tempPath, path); err != nil {
		return fmt.Errorf("replace approval store: %w", err)
	}
	return nil
}

func cleanup(state *diskState, now time.Time) {
	for index := range state.Requests {
		request := &state.Requests[index]
		if (request.Status == StatusPending || request.Status == StatusApproved) && !request.ExpiresAt.After(now) {
			request.Status = StatusExpired
			request.ResolvedAt = now
		}
	}
}

func sameBinding(left, right Request) bool {
	return left.ActionFingerprint == right.ActionFingerprint && left.Workspace == right.Workspace && left.PolicyDigest == right.PolicyDigest
}

func newID() (string, error) {
	raw := make([]byte, 10)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return "apr_" + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)), nil
}
