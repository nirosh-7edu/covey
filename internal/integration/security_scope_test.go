package integration

// Security case 8 — an ACCESS.md scope must limit what an agent can do.
//
// ACCESS.md says `- system: m365 scope: read`. Registry.HasAccess can match a
// scope, but its only caller, brokerCredential (orchestrator.go), passes an
// empty scope, which means "any scope"; decideAction checks the tool allowlist
// and the guard rails and never the scope; and the plugin's Execute receives a
// bare Credential with no scope in it. So `scope: read` is a label: a
// read-only mail agent can call a write action such as send_mail.
//
// The test drives the orchestrator's own gate for an action run as a colleague
// (Orchestrator.ActAs, which mirrors the agent's path: tool assignment, guard
// rails, credential broker, then Execute) with a stub system that has a read
// and a send action. Mock only; gated: COVEY_SECTEST=1.

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/benjaminLedel/covey-plugin-sdk/target"
)

var mailTestCalls struct {
	sync.Mutex
	calls []string // "action" per Execute that actually ran
}

func mailTestRan() []string {
	mailTestCalls.Lock()
	defer mailTestCalls.Unlock()
	return append([]string(nil), mailTestCalls.calls...)
}

type mailTestSystem struct{}

func init() {
	target.Register(target.Descriptor{
		Name: "mailtest", Label: "Mailtest", Kind: "builtin", BaseURLOptional: true,
		Scopes: []string{"read", "write"},
		System: mailTestSystem{},
	})
}

func (mailTestSystem) Name() string { return "mailtest" }
func (mailTestSystem) ActionSubject(action string, _ json.RawMessage) string {
	return "mailtest:" + action
}
func (mailTestSystem) PromptDoc() string { return "" }
func (mailTestSystem) Execute(_ context.Context, action string, _ json.RawMessage, _ target.Credential) (any, error) {
	if action != "read" && action != "send" {
		return nil, errors.New("unknown action " + action)
	}
	mailTestCalls.Lock()
	mailTestCalls.calls = append(mailTestCalls.calls, action)
	mailTestCalls.Unlock()
	return map[string]any{"ok": true}, nil
}

// mailTestAgent creates an agent whose ACCESS.md holds the given line (empty =
// no line for mailtest at all) and gives it the credential.
func (s *stack) mailTestAgent(t *testing.T, slug, accessLine string) (a struct{ id, slug string }, run func(action string) error) {
	t.Helper()
	ctx := context.Background()
	agent, err := s.registry.Create(ctx, s.orgID, slug, "Mail agent", "mock", &s.adminID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.registry.SaveConfig(ctx, agent.ID, map[string]string{
		"SOUL.md":   "# Mail agent\n\n## Role\nMail.",
		"ACCESS.md": accessLine,
	}, &s.adminID); err != nil {
		t.Fatal(err)
	}
	if err := s.targets.SetEnabled(ctx, s.orgID, "mailtest", true); err != nil {
		t.Fatal(err)
	}
	if err := s.secrets.PutAgent(ctx, s.orgID, agent.ID, "mailtest_token", "tok-"+slug); err != nil {
		t.Fatal(err)
	}
	return struct{ id, slug string }{agent.ID.String(), slug}, func(action string) error {
		_, err := s.orch.ActAs(ctx, agent, "mailtest", action, json.RawMessage(`{}`), "")
		return err
	}
}

// TestSec08_ReadOnlyScopeBlocksAWriteAction — the case. FAIL = a write action
// ran for an agent whose ACCESS.md grants only `read`.
func TestSec08_ReadOnlyScopeBlocksAWriteAction(t *testing.T) {
	secTest(t)
	s := newStack(t)
	_, run := s.mailTestAgent(t, "reader", "- system: mailtest scope: read\n")

	if err := run("send"); err == nil {
		t.Errorf("the write action `send` ran for an agent whose ACCESS.md grants only "+
			"`scope: read` (actions that executed: %v) — scopes are not enforced "+
			"(orchestrator.go brokerCredential passes scope \"\" to HasAccess)", mailTestRan())
	}
}

// _control: (1) the read action must run for the same read-only agent, and
// (2) an agent with no ACCESS.md line for the system must be refused — that
// one IS enforced, so it proves the harness can see a refusal.
func TestSec08_ReadOnlyScopeBlocksAWriteAction_control(t *testing.T) {
	secTest(t)
	s := newStack(t)

	_, runReader := s.mailTestAgent(t, "reader2", "- system: mailtest scope: read\n")
	before := len(mailTestRan())
	if err := runReader("read"); err != nil {
		t.Fatalf("control broken: the read action should run for a read-scoped agent: %v", err)
	}
	if len(mailTestRan()) != before+1 {
		t.Fatalf("control broken: the read action did not reach Execute")
	}

	_, runNoAccess := s.mailTestAgent(t, "stranger", "- system: gitlab scope: read\n")
	err := runNoAccess("read")
	if err == nil || !strings.Contains(err.Error(), "no access per ACCESS.md") {
		t.Fatalf("control broken: an agent with no ACCESS.md line for the system must be refused, got: %v", err)
	}
}
