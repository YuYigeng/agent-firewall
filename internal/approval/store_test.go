package approval

import (
	"context"
	"testing"
	"time"
)

func TestApprovalBindingAndSingleUse(t *testing.T) {
	store := New(t.TempDir(), time.Minute)
	ctx := context.Background()
	created, err := store.Create(ctx, Request{
		ActionFingerprint: "sha256:action", Workspace: "/work", PolicyDigest: "sha256:policy",
		RuleID: "ask", Reason: "review", Risk: "high",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Resolve(ctx, created.ID, true); err != nil {
		t.Fatal(err)
	}
	wrong, err := store.Consume(ctx, "sha256:action", "/other", "sha256:policy")
	if err != nil || wrong != nil {
		t.Fatalf("wrong binding consumed: %#v, %v", wrong, err)
	}
	consumed, err := store.Consume(ctx, "sha256:action", "/work", "sha256:policy")
	if err != nil || consumed == nil {
		t.Fatalf("expected consume: %#v, %v", consumed, err)
	}
	again, err := store.Consume(ctx, "sha256:action", "/work", "sha256:policy")
	if err != nil || again != nil {
		t.Fatalf("grant reused: %#v, %v", again, err)
	}
}

func TestApprovalDeduplicatesPendingRequest(t *testing.T) {
	store := New(t.TempDir(), time.Minute)
	ctx := context.Background()
	request := Request{ActionFingerprint: "a", Workspace: "w", PolicyDigest: "p", RuleID: "r"}
	first, err := store.Create(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.Create(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if first.ID != second.ID {
		t.Fatalf("ids differ: %s != %s", first.ID, second.ID)
	}
}

func TestDeniedRequestSuppressesIdenticalPromptUntilExpiry(t *testing.T) {
	store := New(t.TempDir(), time.Minute)
	ctx := context.Background()
	request := Request{ActionFingerprint: "a", Workspace: "w", PolicyDigest: "p", RuleID: "r"}
	first, err := store.Create(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Resolve(ctx, first.ID, false); err != nil {
		t.Fatal(err)
	}
	second, err := store.Create(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if second.ID != first.ID || second.Status != StatusDenied {
		t.Fatalf("denial was not retained: %#v", second)
	}
}
