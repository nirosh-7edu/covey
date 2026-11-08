package orchestrator

// Security case 7 — covey:create_task and covey:message must be checked by
// the CONTROL PLANE against guard rails, not only by the daemon's own
// courtesy call to checkAction before it asks for one.
//
// actionproxy.go's run() (internal/daemon/actionproxy.go) says plainly:
// "'covey' is not an external target system but a meta action towards the
// control plane itself (no credentials, no guard-rail check)" and routes
// straight to controlPlane(), which for create_task/message calls
// checkAction ITSELF, as their own first step, before ever sending the
// actual RequestCreateTask/RequestMessage. That is client-side discipline:
// a forged or modified daemon can skip straight to sending
// TypeRequestCreateTask/TypeRequestMessage, and createAgentTask/
// messageHuman — the control-plane handlers those message types reach
// (handleDaemonMessage's dispatch, orchestrator.go) — never call
// guardrails.Evaluate, decideAction, or anything like it themselves.
//
// This test calls createAgentTask directly, exactly as the dispatch table
// does for TypeRequestCreateTask, with NO RequestApproval ever sent first —
// standing in for the forged message the daemon would otherwise have sent,
// since the handler cannot tell the difference between the two: its
// signature takes the decoded payload, not the wire frame that carried it.
//
// A minimal, self-contained Postgres-backed fixture: this package has no
// existing DB-backed test harness (internal/integration's is the only one in
// the repo, and its helpers are unexported there — not reachable from here,
// and besides, calling the unexported handler directly IS the point of this
// test, which only this package can do). Mock only. Gated: COVEY_SECTEST=1.

import (
	"context"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"

	"covey/internal/agents"
	"covey/internal/backlog"
	"covey/internal/daemon"
	"covey/internal/db"
	"covey/internal/guardrails"
	"covey/internal/observability"
	"covey/migrations"
)

func secTest(t *testing.T) {
	t.Helper()
	if os.Getenv("COVEY_SECTEST") != "1" {
		t.Skip("security case: set COVEY_SECTEST=1 to run")
	}
}

// sec07Stack is a minimal, throwaway-database fixture: just enough wiring for
// createAgentTask (Registry, Backlog, Obs) plus Rails, to prove a deny rule
// on its subject has no effect when the handler is reached directly.
type sec07Stack struct {
	orgID    uuid.UUID
	adminID  uuid.UUID
	registry *agents.Registry
	backlog  *backlog.Store
	rails    *guardrails.Store
	orch     *Orchestrator
}

func sec07NewStack(t *testing.T) *sec07Stack {
	t.Helper()
	ctx := context.Background()

	adminURL := envOrSec07("COVEY_TEST_DATABASE_URL", "postgres://covey:covey@localhost:5433/covey?sslmode=disable")
	admin, err := db.Connect(ctx, adminURL)
	if err != nil {
		t.Skipf("no test Postgres at %s: %v", adminURL, err)
	}
	t.Cleanup(admin.Close)

	dbName := "covey_sec07_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:12]
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+dbName); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		admin.Exec(context.Background(), "DROP DATABASE "+dbName+" WITH (FORCE)")
	})

	u, _ := url.Parse(adminURL)
	u.Path = "/" + dbName
	pool, err := db.Connect(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if _, err := db.MigrateUp(ctx, pool, migrations.FS); err != nil {
		t.Fatal(err)
	}

	s := &sec07Stack{
		registry: agents.NewRegistry(pool),
		backlog:  backlog.NewStore(pool),
		rails:    guardrails.NewStore(pool),
	}
	s.orch = New(Options{
		Pool: pool, Registry: s.registry, Backlog: s.backlog,
		Obs: observability.NewStore(pool), Rails: s.rails,
	})

	s.orgID = uuid.New()
	if _, err := pool.Exec(ctx, "INSERT INTO organizations (id, name) VALUES ($1,'Sec07-Org')", s.orgID); err != nil {
		t.Fatal(err)
	}
	s.adminID = uuid.New()
	accountID := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO accounts (id, email, password_hash, display_name, email_verified_at)
		VALUES ($1,'admin@sec07.local','x','Admin',now())`, accountID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO humans (id, org_id, account_id, email, display_name, password_hash, role)
		VALUES ($1,$2,$3,'admin@sec07.local','Admin','x','org_admin')`, s.adminID, s.orgID, accountID); err != nil {
		t.Fatal(err)
	}
	return s
}

func envOrSec07(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// TestSec07_ForgedCreateTaskBypassesGuardRails — the case. FAIL = a deny_action
// rule on covey:create_task had no effect because the handler the message
// type dispatches to never consults guard rails itself.
func TestSec07_ForgedCreateTaskBypassesGuardRails(t *testing.T) {
	secTest(t)
	s := sec07NewStack(t)
	ctx := context.Background()

	agent, err := s.registry.Create(ctx, s.orgID, "requester", "Requester", "mock", &s.adminID)
	if err != nil {
		t.Fatal(err)
	}
	parent, err := s.backlog.Create(ctx, s.orgID, agent.ID, "Parent task", "do the thing", "manual", 3)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := s.rails.Create(ctx, guardrails.Rule{
		OrgID: s.orgID, ScopeLevel: "global", RuleType: guardrails.RuleDenyAction,
		Pattern: "covey:create_task", Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}

	// No RequestApproval was ever sent — this stands in for a forged
	// TypeRequestCreateTask message reaching the control plane directly.
	resp := s.orch.createAgentTask(ctx, agent, parent.ID, daemon.RequestCreateTask{
		RequestID: uuid.NewString(), Title: "Forged subtask", Body: "created with no guard-rail check at all",
	})

	if resp.OK {
		t.Errorf("createAgentTask created a task (id=%s) despite a deny_action rule on "+
			"`covey:create_task` — the handler for TypeRequestCreateTask never evaluates guard "+
			"rails itself (orchestrator.go createAgentTask); enforcement exists only in the "+
			"daemon's own actionproxy.createTask, which a forged message skips entirely", resp.TaskID)
	}
}

// _control: the SAME call, with NO deny rule in place, must succeed — proving
// createAgentTask's own limits (depth/chain/width/duplicate) are not what is
// refusing it above, and isolating the finding to "guard rails specifically
// are never consulted here" rather than "the handler refuses everything".
func TestSec07_ForgedCreateTaskBypassesGuardRails_control(t *testing.T) {
	secTest(t)
	s := sec07NewStack(t)
	ctx := context.Background()

	agent, err := s.registry.Create(ctx, s.orgID, "requester2", "Requester2", "mock", &s.adminID)
	if err != nil {
		t.Fatal(err)
	}
	parent, err := s.backlog.Create(ctx, s.orgID, agent.ID, "Parent task", "do the thing", "manual", 3)
	if err != nil {
		t.Fatal(err)
	}

	resp := s.orch.createAgentTask(ctx, agent, parent.ID, daemon.RequestCreateTask{
		RequestID: uuid.NewString(), Title: "Ordinary subtask", Body: "no rule exists at all",
	})
	if !resp.OK {
		t.Fatalf("control broken: with no guard rail at all, createAgentTask must succeed, got error: %s", resp.Error)
	}
}
