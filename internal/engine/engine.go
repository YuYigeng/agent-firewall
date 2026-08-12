package engine

import (
	"context"
	"fmt"

	"github.com/YuYigeng/agent-firewall/internal/action"
	"github.com/YuYigeng/agent-firewall/internal/approval"
	"github.com/YuYigeng/agent-firewall/internal/audit"
	"github.com/YuYigeng/agent-firewall/internal/policy"
	"github.com/YuYigeng/agent-firewall/internal/redact"
)

type Engine struct {
	Policy    *policy.Policy
	Approvals *approval.Store
	Ledger    *audit.Ledger
}

func (e *Engine) Decide(ctx context.Context, observer string, a action.Action, nativeApproval bool) (policy.Decision, error) {
	if e.Policy == nil || e.Approvals == nil || e.Ledger == nil {
		return policy.Decision{}, fmt.Errorf("engine is not fully configured")
	}
	decision, err := e.Policy.Evaluate(a)
	if err != nil {
		return policy.Decision{}, fmt.Errorf("evaluate action: %w", err)
	}
	decision.Reason = redact.SafeReason(decision.RuleID, decision.Reason)
	if decision.Decision == policy.DecisionAsk && !nativeApproval {
		grant, err := e.Approvals.Consume(ctx, decision.ActionFingerprint, a.Workspace, decision.PolicyDigest)
		if err != nil {
			return policy.Decision{}, fmt.Errorf("consume approval: %w", err)
		}
		if grant != nil {
			originalRule := decision.RuleID
			decision.Decision = policy.DecisionAllow
			decision.RuleID = "approved:" + originalRule
			decision.Reason = "Allowed by one-shot human approval"
			decision.ApprovalID = grant.ID
		} else {
			request, err := e.Approvals.Create(ctx, approval.Request{
				ActionFingerprint: decision.ActionFingerprint,
				Workspace:         a.Workspace,
				PolicyDigest:      decision.PolicyDigest,
				RuleID:            decision.RuleID,
				Reason:            decision.Reason,
				Risk:              string(decision.Risk),
			})
			if err != nil {
				return policy.Decision{}, fmt.Errorf("create approval: %w", err)
			}
			decision.ApprovalID = request.ID
			if request.Status == approval.StatusDenied {
				decision.Decision = policy.DecisionDeny
				decision.RuleID = "human-denied:" + decision.RuleID
				decision.Reason = "Denied by a recent human approval decision"
			}
		}
	}
	if _, err := e.Ledger.AppendDecision(ctx, observer, a, decision); err != nil {
		return policy.Decision{}, fmt.Errorf("append decision evidence: %w", err)
	}
	return decision, nil
}

func (e *Engine) RecordCompletion(ctx context.Context, observer string, a action.Action, metadata map[string]any) error {
	if e.Ledger == nil {
		return fmt.Errorf("audit ledger is not configured")
	}
	if _, err := e.Ledger.AppendCompletion(ctx, observer, a, metadata); err != nil {
		return fmt.Errorf("append completion evidence: %w", err)
	}
	return nil
}
