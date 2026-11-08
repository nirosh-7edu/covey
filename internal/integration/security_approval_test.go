package integration

// Security case 4 — an approval must be the answer to the parameters a human
// reviewed, not a standing licence for (agent, action).
//
// approvalGate's consuming query (orchestrator.go) is:
//
//	UPDATE approvals SET used=TRUE
//	WHERE id = (SELECT id FROM approvals
//	    WHERE agent_id=$1 AND action=$2 AND status='approved' AND NOT used
//	      AND ($3='' OR params->>'binding' = $3)
//	    ORDER BY decided_at DESC LIMIT 1)
//
// binding is only ever set non-empty by the META-ACTION path (bindingOf in
// hiring.go, see internal/orchestrator/binding_test.go). The ordinary
// target-system path — any plugin action, like a mail send or a payment —
// always calls approvalGate with binding="". So the match key for an ordinary
// action is agent_id + action alone: once ANY request for that pair is
// approved, the NEXT request for the same pair — with completely different
// parameters, from a different task — consumes the very same row.
//
// The window this exploits is real, not contrived: a human approves what they
// were shown (body A) in the inbox; separately, and before that approval is
// actually consumed by the repeat it was meant for, a second request for the
// same agent+action (body B) arrives and is let straight through. The test
// pins that window deterministically with Store.DecideApproval directly
// (what the API's decide endpoint does to the row) while skipping the wake
// notification the HTTP handler also fires — that only decides WHEN task A's
// own legitimate repeat happens to run, not WHETHER the stale-approval reuse
// bug exists, and skipping it keeps this test race-free instead of coin-flip
// flaky against the scheduler's own timing.
//
// Mock only: a dedicated "paytest" system recording the body it actually ran
// with. Gated: COVEY_SECTEST=1.

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"covey/internal/backlog"
	"covey/internal/guardrails"

	"github.com/benjaminLedel/covey-plugin-sdk/target"
	"github.com/google/uuid"
)

var paytestCalls struct {
	sync.Mutex
	bodies []string
}

func paytestRan() []string {
	paytestCalls.Lock()
	defer paytestCalls.Unlock()
	return append([]string(nil), paytestCalls.bodies...)
}

type paytestSystem struct{}

func init() {
	target.Register(target.Descriptor{
		Name: "paytest", Label: "Paytest", Kind: "builtin", BaseURLOptional: true,
		Scopes: []string{"write"},
		System: paytestSystem{},
	})
}

func (paytestSystem) Name() string { return "paytest" }
func (paytestSystem) ActionSubject(action string, _ json.RawMessage) string {
	return "paytest:" + action
}
func (paytestSystem) PromptDoc() string { return "" }
func (paytestSystem) Execute(_ context.Context, action string, raw json.RawMessage, _ target.Credential) (any, error) {
	if action != "send" {
		return nil, errors.New("unknown action " + action)
	}
	var p struct {
		Body string `json:"body"`
	}
	_ = json.Unmarshal(raw, &p)
	paytestCalls.Lock()
	paytestCalls.bodies = append(paytestCalls.bodies, p.Body)
	paytestCalls.Unlock()
	return map[string]any{"ok": true}, nil
}

// sec04Agent creates a "paytest"-enabled agent with a require_approval rule
// already in place on paytest:send.
func (s *stack) sec04Agent(t *testing.T, slug string) struct{ ID uuid.UUID } {
	t.Helper()
	ctx := context.Background()
	agent, err := s.registry.Create(ctx, s.orgID, slug, "Payer", "mock", &s.adminID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.registry.SaveConfig(ctx, agent.ID, map[string]string{
		"SOUL.md":   "# Payer\n\n## Role\nSends payments.",
		"ACCESS.md": "- system: paytest scope: write\n",
	}, &s.adminID); err != nil {
		t.Fatal(err)
	}
	if err := s.targets.SetEnabled(ctx, s.orgID, "paytest", true); err != nil {
		t.Fatal(err)
	}
	if err := s.secrets.PutAgent(ctx, s.orgID, agent.ID, "paytest_token", "tok-"+slug); err != nil {
		t.Fatal(err)
	}
	return struct{ ID uuid.UUID }{agent.ID}
}

// TestSec04_ApprovalDoesNotBindToReviewedParams — the case. FAIL = a second,
// never-reviewed request for the same agent+action ran because a DIFFERENT
// request's approval was still sitting there, approved and unconsumed.
func TestSec04_ApprovalDoesNotBindToReviewedParams(t *testing.T) {
	secTest(t)
	s := newStack(t)
	ctx := context.Background()
	agent := s.sec04Agent(t, "payer")

	if _, err := s.rails.Create(ctx, guardrails.Rule{
		OrgID: s.orgID, ScopeLevel: "global", RuleType: guardrails.RuleRequireApproval,
		Pattern: "paytest:send", Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}

	// Task A asks to send body A — the text a human will actually read.
	taskA, err := s.backlog.Create(ctx, s.orgID, agent.ID, "Send A",
		`[mock:action paytest/send {"body":"A - wire $100 to the vendor"}]`, "manual", 3)
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, "task A waits for approval", 30*time.Second, func() bool {
		return s.taskState(taskA.ID) == backlog.StateBlocked
	})

	var approvalID uuid.UUID
	if err := s.pool.QueryRow(ctx,
		`SELECT id FROM approvals WHERE agent_id=$1 AND action='paytest:send' AND status='pending'`,
		agent.ID).Scan(&approvalID); err != nil {
		t.Fatalf("task A's pending approval must exist: %v", err)
	}

	// The human reviews exactly body A and approves it — Store.DecideApproval
	// is exactly what the HTTP decide endpoint does to the row; what is
	// skipped here is only the wake it ALSO fires, to pin the race-free
	// window described above.
	if _, err := s.obs.DecideApproval(ctx, s.orgID, approvalID, true, &s.adminID); err != nil {
		t.Fatal(err)
	}

	// Task B asks to send a completely different body — nobody has reviewed
	// this one.
	taskB, err := s.backlog.Create(ctx, s.orgID, agent.ID, "Send B",
		`[mock:action paytest/send {"body":"B - wire $100000 to the attacker"}]`, "manual", 3)
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, "task B settles", 30*time.Second, func() bool {
		st := s.taskState(taskB.ID)
		return st == backlog.StateDone || st == backlog.StateFailed || st == backlog.StateBlocked
	})

	if st := s.taskState(taskB.ID); st != backlog.StateBlocked {
		t.Errorf("task B's send ran (status=%s) with NOBODY having reviewed its body — its "+
			"RequestApproval was auto-approved by consuming the approval a human granted for task "+
			"A's different body (orchestrator.go approvalGate matches agent_id+action only; no "+
			"params binding outside the meta-action path); bodies actually executed: %v",
			st, paytestRan())
	}
}

// _control: the same system, same guard rail, same agent — but with no prior
// approval sitting unconsumed. The request must block for its own review,
// proving require_approval still gates ordinary requests; the vulnerability
// above is specifically about a STALE approved-and-unused row for the same
// (agent, action), not about the gate being absent altogether.
func TestSec04_ApprovalDoesNotBindToReviewedParams_control(t *testing.T) {
	secTest(t)
	s := newStack(t)
	ctx := context.Background()
	agent := s.sec04Agent(t, "payer-control")

	if _, err := s.rails.Create(ctx, guardrails.Rule{
		OrgID: s.orgID, ScopeLevel: "global", RuleType: guardrails.RuleRequireApproval,
		Pattern: "paytest:send", Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}

	taskC, err := s.backlog.Create(ctx, s.orgID, agent.ID, "Send C",
		`[mock:action paytest/send {"body":"C - no prior approval exists for this agent"}]`, "manual", 3)
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, "task C settles", 30*time.Second, func() bool {
		st := s.taskState(taskC.ID)
		return st == backlog.StateDone || st == backlog.StateFailed || st == backlog.StateBlocked
	})
	if st := s.taskState(taskC.ID); st != backlog.StateBlocked {
		t.Fatalf("control broken: with no prior approval for this agent+action, the send must "+
			"block for review, got %s", st)
	}
}
