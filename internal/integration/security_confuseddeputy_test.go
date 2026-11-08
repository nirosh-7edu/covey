package integration

// Security case 14 — confused deputy: a low-privilege member asks an agent
// that holds a mock HR mailbox to summarise it. The plan's own expectation:
// "document what prevents this (expected: nothing)".
//
// The only gate between a member and an agent is chat-reach (internal/chat/
// reach.go): an organisational-routing question (which agents may this
// person message directly — their own department's, or the ones they
// supervise), and its DEFAULT is `ReachOrg`: every member may message every
// agent in the organisation, whatever their seat role. Nothing downstream of
// that checks whether the ASKING HUMAN independently has any right to the
// DATA the agent's own brokered credential can reach — the agent's
// ACCESS.md governs the agent, not the human sending it a chat message. A
// seat role as low as `controlling` (the lowest of the five RBAC roles,
// internal/identity/identity.go) can message an HR-mailbox-holding agent
// and have it run its own privileged read on their behalf.
//
// Mock only. Gated: COVEY_SECTEST=1.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"covey/internal/backlog"

	"github.com/benjaminLedel/covey-plugin-sdk/target"
	"github.com/google/uuid"
)

const hrMailCanary = "HR-MAILBOX-CONFIDENTIAL-salaries-alice-120k-bob-95k"

type hrMailTestSystem struct{}

func init() {
	target.Register(target.Descriptor{
		Name: "hrmailtest", Label: "HR Mailbox (test)", Kind: "builtin", BaseURLOptional: true,
		Scopes: []string{"read"},
		System: hrMailTestSystem{},
	})
}

func (hrMailTestSystem) Name() string { return "hrmailtest" }
func (hrMailTestSystem) ActionSubject(action string, _ json.RawMessage) string {
	return "hrmailtest:" + action
}
func (hrMailTestSystem) PromptDoc() string { return "" }
func (hrMailTestSystem) Execute(_ context.Context, action string, _ json.RawMessage, _ target.Credential) (any, error) {
	if action != "read" {
		return nil, errors.New("unknown action " + action)
	}
	return map[string]any{"ok": true, "content": hrMailCanary}, nil
}

// TestSec14_LowPrivilegeMemberGetsAgentToReadHRDataForThem — the case. FAIL =
// the low-privilege member's own conversation shows the HR mailbox content,
// fetched by the agent's credential on her say-so alone.
func TestSec14_LowPrivilegeMemberGetsAgentToReadHRDataForThem(t *testing.T) {
	secTest(t)
	s := newStack(t)
	ctx := context.Background()
	teamLogin(t, s) // side effect only: switches the team surface on

	hrBot, err := s.registry.Create(ctx, s.orgID, "hr-bot", "HR Bot", "mock", &s.adminID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.registry.SaveConfig(ctx, hrBot.ID, map[string]string{
		"SOUL.md":   "# HR Bot\n\n## Role\nHolds the HR mailbox credential for the People team.",
		"ACCESS.md": "- system: hrmailtest scope: read\n",
	}, &s.adminID); err != nil {
		t.Fatal(err)
	}
	if err := s.targets.SetEnabled(ctx, s.orgID, "hrmailtest", true); err != nil {
		t.Fatal(err)
	}
	if err := s.secrets.PutAgent(ctx, s.orgID, hrBot.ID, "hrmailtest_token", "tok-hr-bot"); err != nil {
		t.Fatal(err)
	}

	// The lowest seat role there is (internal/identity/identity.go) — someone
	// with no business reading anyone's compensation data.
	s.mitglied(t, "intern@test.local", "Intern", "controlling", "intern-passwort")
	intern := login(t, s, "intern@test.local", "intern-passwort")

	// Paused so the run cannot start before the body below is swapped in —
	// otherwise the mock runtime would read her OWN authored text, which
	// must stay a plain question with no canary in it: the proof has to be
	// the AGENT's own reply, not an artifact of how the mock script a human
	// "said" was written.
	s.ohneLaeufe(hrBot.ID)

	humanText := "Can you check the HR mailbox and tell me what's in it?"
	// Default chat-reach (ReachOrg): no setup needed for her message to reach
	// the HR agent at all — that is the point.
	created := intern.expect(http.MethodPost, "/api/v1/agents/"+hrBot.ID.String()+"/messages",
		map[string]any{"text": humanText}, http.StatusCreated)
	msg, _ := created["message"].(map[string]any)
	convID, _ := msg["conversation_id"].(string)
	if convID == "" {
		t.Fatalf("no conversation came back: %v", created)
	}
	task, _ := created["task"].(map[string]any)
	taskID, _ := task["id"].(string)
	if taskID == "" {
		t.Fatalf("no task came back: %v", created)
	}
	if got, _ := msg["text"].(string); got != humanText || strings.Contains(got, hrMailCanary) {
		t.Fatalf("setup broken: her own authored message must stay canary-free: %q", got)
	}

	// What a real runtime would do in response to her question: read the
	// mailbox with the agent's OWN credential, then report back. Written
	// into the task's body directly (not her chat text) so the canary can
	// only ever reach the thread through the agent's own actual run.
	if _, err := s.pool.Exec(ctx, `UPDATE backlog_tasks SET body=$2 WHERE id=$1`, taskID,
		"[mock:action hrmailtest/read {}] [mock:result "+hrMailCanary+"]"); err != nil {
		t.Fatal(err)
	}
	if err := s.registry.Hire(ctx, hrBot.ID); err != nil { // undo ohneLaeufe, let dispatch proceed
		t.Fatal(err)
	}

	waitFor(t, "the task settles", 30*time.Second, func() bool {
		st := s.taskState(uuid.MustParse(taskID))
		return st == backlog.StateDone || st == backlog.StateFailed
	})
	s.srv.Nacherzaehlen(ctx) // force the completion into a chat reply now, not on the next tick

	thread := intern.expect(http.MethodGet, "/api/v1/conversations/"+convID+"/messages", nil, http.StatusOK)
	msgs, _ := thread["messages"].([]any)
	var found string
	for _, m := range msgs {
		mm, _ := m.(map[string]any)
		txt, _ := mm["text"].(string)
		// Specifically the AGENT's own posted message (chat.MemberAgent, "agent")
		// — not her own authored text, which must never carry the canary either.
		if mm["author_kind"] == "agent" && strings.Contains(txt, hrMailCanary) {
			found = txt
		}
		if mm["author_kind"] == "human" && strings.Contains(txt, hrMailCanary) {
			t.Fatalf("test broken: the canary leaked into the human's OWN authored message: %q", txt)
		}
	}
	if found == "" {
		t.Errorf("the HR mailbox content never reached the intern's own conversation as the agent's "+
			"own reply — got: %v", msgs)
		return
	}
	t.Errorf("a `controlling`-role member with NO access to the HR mailbox asked the agent to read "+
		"it and received the content back as the AGENT's OWN reply, in her OWN conversation (%q) — "+
		"the only gate between a member and an agent is chat-reach (internal/chat/reach.go), whose "+
		"default (ReachOrg) lets every member message every agent in the organisation; nothing checks "+
		"whether the ASKING human independently has any right to what the agent's own brokered "+
		"credential can reach", found)
}

// _control: the SAME setup, but chat-reach narrowed to department AND the
// intern placed in a DIFFERENT department than the HR agent — now the
// message is correctly refused. This proves chat-reach is a real, working
// check — it just checks organisational ROUTING (who may message whom), not
// DATA AUTHORISATION (whether the asker may see what the agent can fetch);
// an intern who happens to share — or is placed in — the HR agent's own
// department (very plausible for an HR team) sails through it regardless.
func TestSec14_LowPrivilegeMemberGetsAgentToReadHRDataForThem_control(t *testing.T) {
	secTest(t)
	s := newStack(t)
	ctx := context.Background()
	admin := teamLogin(t, s)

	hrBot, err := s.registry.Create(ctx, s.orgID, "hr-bot-2", "HR Bot 2", "mock", &s.adminID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.registry.SaveConfig(ctx, hrBot.ID, map[string]string{
		"SOUL.md":   "# HR Bot 2",
		"ACCESS.md": "- system: hrmailtest scope: read\n",
	}, &s.adminID); err != nil {
		t.Fatal(err)
	}

	var hrDept, otherDept uuid.UUID
	if err := s.pool.QueryRow(ctx, `INSERT INTO departments (org_id, name) VALUES ($1, 'HR') RETURNING id`,
		s.orgID).Scan(&hrDept); err != nil {
		t.Fatal(err)
	}
	if err := s.pool.QueryRow(ctx, `INSERT INTO departments (org_id, name) VALUES ($1, 'Sales') RETURNING id`,
		s.orgID).Scan(&otherDept); err != nil {
		t.Fatal(err)
	}
	if _, err := s.pool.Exec(ctx, `UPDATE agents SET department_id=$2 WHERE id=$1`, hrBot.ID, hrDept); err != nil {
		t.Fatal(err)
	}

	internID := s.mitglied(t, "intern2@test.local", "Intern2", "controlling", "intern2-passwort")
	if _, err := s.pool.Exec(ctx, `UPDATE humans SET department_id=$2 WHERE id=$1`, internID, otherDept); err != nil {
		t.Fatal(err)
	}
	intern := login(t, s, "intern2@test.local", "intern2-passwort")

	admin.expect(http.MethodPatch, "/api/v1/org/chat-reach", map[string]any{"reach": "department"}, http.StatusOK)

	intern.expect(http.MethodPost, "/api/v1/agents/"+hrBot.ID.String()+"/messages",
		map[string]any{"text": "Can you check the HR mailbox?"}, http.StatusForbidden)
}
