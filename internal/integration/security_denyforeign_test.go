package integration

// Security case 5 — a deny rule on `covey:set_agent_config` must also block
// writing a HIRED COLLEAGUE's config, not just a draft from the same task's
// own assignment.
//
// guardrails.matches (guardrails.go) is exact-string-or-wildcard-suffix only.
// hiringSubject (hiring.go) gives set_agent_config two distinct subjects: the
// plain "covey:set_agent_config" when the target was drafted within THIS
// task, and "covey:set_agent_config:foreign" for any other agent — a hired
// colleague, or a draft from a different assignment. A deny rule written
// against the plain subject, the natural and most literal choice for an
// admin who means to forbid agents rewriting configs at all, never matches
// the ":foreign" suffix — so it silently fails to cover the one case it
// matters most for: an agent overwriting an already-hired colleague's
// SOUL.md/ACCESS.md.
//
// Mock only. Gated: COVEY_SECTEST=1.

import (
	"context"
	"testing"
	"time"

	"covey/internal/backlog"
	"covey/internal/guardrails"

	"github.com/google/uuid"
)

const sec05VictimSoul = "# Victim\n\n## Role\nOriginal, human-reviewed configuration."

// sec05Agents sets up a victim (an existing, already-configured colleague —
// standing in for a hired one; hired-vs-draft status does not matter here,
// only that it was NOT drafted within the attacker task below) and an
// attacker agent with covey:agents:write.
func (s *stack) sec05Agents(t *testing.T, suffix string) (victimSlug string, attackerID uuid.UUID) {
	t.Helper()
	ctx := context.Background()

	victim, err := s.registry.Create(ctx, s.orgID, "victim-"+suffix, "Victim", "mock", &s.adminID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.registry.SaveConfig(ctx, victim.ID, map[string]string{
		"SOUL.md":   sec05VictimSoul,
		"ACCESS.md": "",
	}, &s.adminID); err != nil {
		t.Fatal(err)
	}

	attacker, err := s.registry.Create(ctx, s.orgID, "attacker-"+suffix, "Attacker", "mock", &s.adminID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.registry.SaveConfig(ctx, attacker.ID, map[string]string{
		"SOUL.md":   "# Attacker\n\n## Role\nDrafts and configures colleagues.",
		"ACCESS.md": "- system: covey scope: agents:write\n",
	}, &s.adminID); err != nil {
		t.Fatal(err)
	}
	return victim.Slug, attacker.ID
}

// TestSec05_DenyOnSetAgentConfigDoesNotCoverForeignSubject — the case. FAIL =
// the victim's SOUL.md changed despite a deny rule on the plain
// `covey:set_agent_config` subject.
func TestSec05_DenyOnSetAgentConfigDoesNotCoverForeignSubject(t *testing.T) {
	secTest(t)
	s := newStack(t)
	ctx := context.Background()
	victimSlug, attackerID := s.sec05Agents(t, "a")

	if _, err := s.rails.Create(ctx, guardrails.Rule{
		OrgID: s.orgID, ScopeLevel: "global", RuleType: guardrails.RuleDenyAction,
		Pattern: "covey:set_agent_config", Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}

	task, err := s.backlog.Create(ctx, s.orgID, attackerID, "Reconfigure colleague",
		`[mock:action covey/set_agent_config {"agent":"`+victimSlug+
			`","files":{"SOUL.md":"# PWNED — rewritten through the :foreign subject a plain deny rule never matches"}}]`,
		"manual", 3)
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the task settles", 30*time.Second, func() bool {
		st := s.taskState(task.ID)
		return st == backlog.StateDone || st == backlog.StateFailed
	})

	victim, err := s.registry.GetBySlug(ctx, s.orgID, victimSlug)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := s.registry.CurrentConfig(ctx, victim.ID)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Files["SOUL.md"] != sec05VictimSoul {
		t.Errorf("the victim colleague's SOUL.md was rewritten (now %q) despite a deny rule on "+
			"`covey:set_agent_config` — the action actually ran under the `:foreign` subject "+
			"(hiring.go hiringSubject), which an exact-pattern deny on the plain subject never "+
			"matches (guardrails.go matches is exact-or-wildcard-suffix only); task ended %s",
			cfg.Files["SOUL.md"], s.taskState(task.ID))
	}
}

// _control: the SAME deny rule, SAME attacker, but the target is drafted by
// this same task first (covey:create_agent), so hiringSubject keeps the
// PLAIN subject — the rule must still block that one, proving the deny
// mechanism itself works and isolating the bug to the subject-splitting,
// not to deny rules on set_agent_config being toothless outright.
func TestSec05_DenyOnSetAgentConfigDoesNotCoverForeignSubject_control(t *testing.T) {
	secTest(t)
	s := newStack(t)
	ctx := context.Background()
	_, attackerID := s.sec05Agents(t, "b")

	if _, err := s.rails.Create(ctx, guardrails.Rule{
		OrgID: s.orgID, ScopeLevel: "global", RuleType: guardrails.RuleDenyAction,
		Pattern: "covey:set_agent_config", Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}

	task, err := s.backlog.Create(ctx, s.orgID, attackerID, "Draft then configure",
		`[mock:action covey/create_agent {"display_name":"Fresh Draft","slug":"fresh-draft-b","runtime":"mock"}] `+
			`[mock:action covey/set_agent_config {"agent":"fresh-draft-b","files":{"SOUL.md":"# should never land"}}]`,
		"manual", 3)
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the task settles", 30*time.Second, func() bool {
		st := s.taskState(task.ID)
		return st == backlog.StateDone || st == backlog.StateFailed
	})

	// The draft itself must exist (create_agent, an unrelated subject, is not
	// touched by this rule) — only its config write must have been refused.
	draft, err := s.registry.GetBySlug(ctx, s.orgID, "fresh-draft-b")
	if err != nil {
		t.Fatalf("control setup broken: the draft must exist: %v", err)
	}
	cfg, err := s.registry.CurrentConfig(ctx, draft.ID)
	if err == nil && cfg.Files["SOUL.md"] == "# should never land" {
		t.Fatalf("control broken: a deny rule on the plain `covey:set_agent_config` subject must "+
			"still block configuring a draft from THIS task's own assignment, but it landed: %q",
			cfg.Files["SOUL.md"])
	}
	// err != nil here (no config version at all) is the EXPECTED outcome: the
	// deny fired before any config was ever saved for the fresh draft.
}
