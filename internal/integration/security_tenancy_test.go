package integration

// Security cases on tenancy and authentication (priority 2). Gated like every
// security case: COVEY_SECTEST=1. Mock only; the addresses are fake.

import (
	"encoding/json"
	"net/http"
	"testing"
)

// loginStatus attempts a login and returns the HTTP status instead of
// aborting the test, so a case can assert that a login must FAIL.
func loginStatus(t *testing.T, s *stack, email, password string) int {
	t.Helper()
	c := &apiClient{t: t, base: s.http.URL, http: &http.Client{Jar: newJar()}}
	resp := c.do(http.MethodPost, "/api/v1/auth/login",
		map[string]string{"email": email, "password": password})
	resp.Body.Close()
	return resp.StatusCode
}

// Case 9 — an administrator of organisation B must not be able to take over an
// account that belongs to someone in organisation A.
//
// org.CreateHuman looks the address up in the GLOBAL accounts table and, when
// the account exists, attaches a seat in the caller's organisation to it
// without the account holder's say (internal/org/org.go CreateHuman).
// UpdateHuman then writes a new password onto that shared account row
// (UpdateHuman: "UPDATE accounts SET password_hash"), so the next login as the
// victim — in organisation A — uses the attacker's password.
//
// FAIL = the takeover works.
func TestSec09_OrgBAdminCannotTakeOverAnOrgAAccount(t *testing.T) {
	secTest(t)
	s := newStack(t)
	s.alsSystemadmin(t) // only so the test can create org B; the attacker is NOT one
	adminA := login(t, s, "admin@test.local", "admin-passwort")

	const (
		victim    = "victim@orga.test"
		victimPW  = "victim-original-pw"
		attackPW1 = "attacker-chosen-pw" // sent when seating the victim in org B
		attackPW2 = "takeover-pw-123"    // set afterwards through PATCH
	)
	adminA.expect(http.MethodPost, "/api/v1/users", map[string]string{
		"email": victim, "display_name": "Victim", "role": "agent_owner", "password": victimPW,
	}, http.StatusCreated)

	adminA.expect(http.MethodPost, "/api/v1/platform/orgs", map[string]string{
		"name": "Org B", "admin_email": "attacker@orgb.test",
		"admin_name": "Attacker", "admin_password": "attacker-own-pw",
	}, http.StatusCreated)
	attacker := login(t, s, "attacker@orgb.test", "attacker-own-pw")
	// Precondition: the attacker is an org administrator, nothing more.
	attacker.expect(http.MethodGet, "/api/v1/platform/orgs", nil, http.StatusNotFound)

	// Step 1: seat the victim's address in org B.
	resp := attacker.do(http.MethodPost, "/api/v1/users", map[string]string{
		"email": victim, "display_name": "Victim", "role": "agent_owner", "password": attackPW1,
	})
	seated := resp.StatusCode == http.StatusCreated
	var created map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&created)
	resp.Body.Close()

	// Step 2: if that worked, reset the password through the seat.
	patched := false
	if seated {
		id, _ := created["id"].(string)
		r := attacker.do(http.MethodPatch, "/api/v1/users/"+id, map[string]string{"password": attackPW2})
		patched = r.StatusCode == http.StatusOK
		r.Body.Close()
	}

	// Verdict: the victim is untouched.
	if got := loginStatus(t, s, victim, victimPW); got != http.StatusOK {
		t.Errorf("the victim's own password no longer works (HTTP %d); seated in org B: %v, password reset through the seat: %v",
			got, seated, patched)
	}
	for _, pw := range []string{attackPW1, attackPW2} {
		if got := loginStatus(t, s, victim, pw); got == http.StatusOK {
			t.Errorf("the org B administrator can log in as the org A account with %q (seated: %v, reset: %v)",
				pw, seated, patched)
		}
	}

	// Where does a login with the attacker's password land? Evidence only —
	// it sizes the impact (org A data, or just the attacker's own org).
	if patched {
		hijacked := login(t, s, victim, attackPW2)
		me := hijacked.expect(http.MethodGet, "/api/v1/auth/me", nil, http.StatusOK)
		t.Logf("hijacked session: org=%v role=%v (org A is %s)", me["OrgID"], me["Role"], s.orgID)
		r := hijacked.do(http.MethodGet, "/api/v1/auth/memberships", nil)
		var mem any
		_ = json.NewDecoder(r.Body).Decode(&mem)
		r.Body.Close()
		t.Logf("memberships of the hijacked account: %v", mem)
	}
}

// TestSec09_..._control proves the check can see a password change at all: the
// victim's OWN organisation administrator resets it (which is allowed), and
// the login probe must then flip. PASS = the detector works.
func TestSec09_OrgBAdminCannotTakeOverAnOrgAAccount_control(t *testing.T) {
	secTest(t)
	s := newStack(t)
	adminA := login(t, s, "admin@test.local", "admin-passwort")

	created := adminA.expect(http.MethodPost, "/api/v1/users", map[string]string{
		"email": "victim@orga.test", "display_name": "Victim", "role": "agent_owner", "password": "victim-original-pw",
	}, http.StatusCreated)
	adminA.expect(http.MethodPatch, "/api/v1/users/"+created["id"].(string),
		map[string]string{"password": "reset-by-own-admin"}, http.StatusOK)

	if got := loginStatus(t, s, "victim@orga.test", "reset-by-own-admin"); got != http.StatusOK {
		t.Fatalf("control broken: the new password does not log in (HTTP %d)", got)
	}
	if got := loginStatus(t, s, "victim@orga.test", "victim-original-pw"); got == http.StatusOK {
		t.Fatalf("control broken: the old password still logs in")
	}
}
