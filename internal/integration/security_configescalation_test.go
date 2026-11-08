package integration

// Security case 6 — an `agents:write` agent rewrites another agent's LIVE
// (hired, already-running) config and system_accesses with no human in the
// loop at all, by default, and the write is not limited to the access the
// WRITING agent itself holds.
//
// The "no human by default" half is spec/20-hiring-and-setup.md's own,
// explicit, documented trade-off (rule 4): set_agent_config reaches every
// colleague the caller did not draft, under its own guard-rail subject
// (covey:set_agent_config:foreign, see case 5 in security_denyforeign_test.go
// for where THAT governance mechanism itself has a gap), and an organisation
// that wants the old boundary back has to set a rule — none is required by
// default. That half is confirmed here for the record, the same way case 2
// records a documented default rather than a surprise.
//
// The second half is not called out anywhere in spec/20 or hiring.go:
// hiringSetConfig has no check at all tying what it writes into a target's
// ACCESS.md to what the WRITING agent's own ACCESS.md holds. An agent with
// nothing but `- system: covey scope: agents:write` — no access to any other
// system whatsoever — can grant an already-hired colleague access to a
// system (and a write scope on it) it never had itself, with zero approval
// event, zero guard-rail rule needed, and zero record of anyone having
// decided this was fine. That is an unbounded privilege-escalation path
// through a proxy agent, not merely "no human reviews it" — worth recording
// explicitly rather than folding into the already-documented first half.
//
// Mock only. Gated: COVEY_SECTEST=1.

import (
	"context"
	"testing"
	"time"

	"covey/internal/backlog"
)

// TestSec06_AgentsWriteGrantsAccessTheWriterNeverHad — the case. The task
// must complete (demonstrating no human was involved) AND the victim's
// ACCESS.md must now hold a system the attacker agent itself was never given.
func TestSec06_AgentsWriteGrantsAccessTheWriterNeverHad(t *testing.T) {
	secTest(t)
	s := newStack(t)
	ctx := context.Background()

	victim, err := s.registry.Create(ctx, s.orgID, "live-colleague", "Live Colleague", "mock", &s.adminID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.registry.SaveConfig(ctx, victim.ID, map[string]string{
		"SOUL.md":   "# Live Colleague\n\n## Role\nHad no system access at all before this test.",
		"ACCESS.md": "",
	}, &s.adminID); err != nil {
		t.Fatal(err)
	}
	// LIVE, not a draft: hired, exactly like case 6 says ("live config").
	if err := s.registry.Hire(ctx, victim.ID); err != nil {
		t.Fatal(err)
	}

	attacker, err := s.registry.Create(ctx, s.orgID, "people-dept", "People Dept", "mock", &s.adminID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.registry.SaveConfig(ctx, attacker.ID, map[string]string{
		"SOUL.md": "# People Dept\n\n## Role\nDrafts and configures colleagues.",
		// Deliberately the ONLY line: no access to "paytest" or anything else
		// besides the platform's own hiring system.
		"ACCESS.md": "- system: covey scope: agents:write\n",
	}, &s.adminID); err != nil {
		t.Fatal(err)
	}

	// No guard rail at all — the organisation's out-of-the-box state.

	task, err := s.backlog.Create(ctx, s.orgID, attacker.ID, "Reconfigure the live colleague",
		`[mock:action covey/set_agent_config {"agent":"live-colleague","files":{"ACCESS.md":"- system: paytest scope: write\n"}}]`,
		"manual", 3)
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the task settles", 30*time.Second, func() bool {
		st := s.taskState(task.ID)
		return st == backlog.StateDone || st == backlog.StateFailed || st == backlog.StateBlocked
	})

	if st := s.taskState(task.ID); st != backlog.StateDone {
		t.Fatalf("expected the write to go straight through with no human step (that half is "+
			"spec/20's own documented trade-off, not what this test is about), got %s", st)
	}

	cfg, err := s.registry.CurrentConfig(ctx, victim.ID)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Files["ACCESS.md"] != "- system: paytest scope: write\n" {
		t.Fatalf("setup broken: the write should have landed, got ACCESS.md=%q", cfg.Files["ACCESS.md"])
	}

	var approvalCount int
	if err := s.pool.QueryRow(ctx,
		`SELECT count(*) FROM approvals WHERE agent_id=$1`, attacker.ID).Scan(&approvalCount); err != nil {
		t.Fatal(err)
	}

	t.Errorf("an agent whose OWN ACCESS.md grants nothing but `covey scope: agents:write` just "+
		"gave an already-hired, live colleague access to `paytest scope: write` — a system the "+
		"writing agent never had itself — with zero approvals created (count=%d) and no guard rail "+
		"required by default: hiringSetConfig (hiring.go) has no check tying what it writes into a "+
		"target's ACCESS.md to the writing agent's own access", approvalCount)
}

// _control: the SAME attacker, SAME path, but granting the target `system:
// covey` (self-propagation) instead of an unrelated system — hiringSetConfig
// DOES refuse that specific content (rule 2, "no self-propagation"), proving
// the function is not a rubber stamp with zero content checks; the gap above
// is specifically "any system OTHER than covey itself", not an absence of
// any check whatsoever.
func TestSec06_AgentsWriteGrantsAccessTheWriterNeverHad_control(t *testing.T) {
	secTest(t)
	s := newStack(t)
	ctx := context.Background()

	victim, err := s.registry.Create(ctx, s.orgID, "live-colleague-2", "Live Colleague 2", "mock", &s.adminID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.registry.SaveConfig(ctx, victim.ID, map[string]string{
		"SOUL.md":   "# Live Colleague 2\n\n## Role\nHad no system access at all before this test.",
		"ACCESS.md": "",
	}, &s.adminID); err != nil {
		t.Fatal(err)
	}
	if err := s.registry.Hire(ctx, victim.ID); err != nil {
		t.Fatal(err)
	}

	attacker, err := s.registry.Create(ctx, s.orgID, "people-dept-2", "People Dept 2", "mock", &s.adminID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.registry.SaveConfig(ctx, attacker.ID, map[string]string{
		"SOUL.md":   "# People Dept 2\n\n## Role\nDrafts and configures colleagues.",
		"ACCESS.md": "- system: covey scope: agents:write\n",
	}, &s.adminID); err != nil {
		t.Fatal(err)
	}

	task, err := s.backlog.Create(ctx, s.orgID, attacker.ID, "Propagate self",
		`[mock:action covey/set_agent_config {"agent":"live-colleague-2","files":{"ACCESS.md":"- system: covey scope: agents:write\n"}}]`,
		"manual", 3)
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the task settles", 30*time.Second, func() bool {
		st := s.taskState(task.ID)
		return st == backlog.StateDone || st == backlog.StateFailed || st == backlog.StateBlocked
	})

	cfg, err := s.registry.CurrentConfig(ctx, victim.ID)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Files["ACCESS.md"] == "- system: covey scope: agents:write\n" {
		t.Fatalf("control broken: hiringSetConfig must refuse granting `system: covey` to another "+
			"agent (rule 2, no self-propagation), but it landed: %q", cfg.Files["ACCESS.md"])
	}
}
