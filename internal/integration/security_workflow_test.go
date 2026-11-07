package integration

// Security case 21 — a workflow action step on system "dev" must not run a
// shell inside the control-plane process.
//
// brokerCredential's own comment says of NoCredentials systems like dev:
// "the actions run entirely inside the sandbox" (orchestrator.go, near 3431).
// But Orchestrator.ActAs (workflowact.go) — the path a workflow's `act` step
// uses to run as a colleague — resolves ANY activated, ACCESS.md-allowed
// system and calls sys.Execute() directly, in the control-plane's own
// process. For "dev" that is covey-plugin-pack/dev.Execute, which runs
// exec.Command on whatever host that process is on. A workflow step's params
// come from engine.render(), which fills {{step.field}} from what an EARLIER
// step reported — including an AI step's own report fields (engine.go act/
// render). So a workflow definition that feeds a report field into a
// dev:exec `cmd` template turns whatever that agent reported into a shell
// command run on the control-plane host.
//
// Mock only: a fake canary and a file written under t.TempDir(), never a real
// command against anything live. Gated like every security case:
// COVEY_SECTEST=1.

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	_ "github.com/benjaminLedel/covey-plugin-pack/dev"
)

func TestSec21_WorkflowDevActionDoesNotRunInTheControlPlane(t *testing.T) {
	secTest(t)
	s := newStack(t)
	ctx := context.Background()

	agent := s.newSupportAgent("coder")
	if _, err := s.registry.SaveConfig(ctx, agent.ID, map[string]string{
		"SOUL.md":   "# Support-Agent\n\n## Role\nSupport.",
		"ACCESS.md": "- system: dev scope: exec\n",
	}, &s.adminID); err != nil {
		t.Fatal(err)
	}
	if err := s.targets.SetEnabled(ctx, s.orgID, "dev", true); err != nil {
		t.Fatal(err)
	}

	canary := newCanary("workflow-rce")
	outFile := filepath.Join(t.TempDir(), "sec21-output.txt")
	// What a workflow definition would write to feed an earlier step's report
	// into this action — here inlined, since the point under test is what
	// ActAs does with the resulting params, not the templating itself.
	cmd := "id -u > " + outFile + "; echo " + canary + " >> " + outFile
	params, _ := json.Marshal(map[string]string{"cmd": cmd})

	if _, err := s.orch.ActAs(ctx, agent, "dev", "exec", params, ""); err != nil {
		t.Fatalf("ActAs(dev, exec) refused the action — if this is the fix, good: %v", err)
	}

	b, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("expected the secure behaviour (no shell ran anywhere reachable from here); "+
			"instead the command did not even reach a file I could find: %v", err)
	}
	out := string(b)
	if !strings.Contains(out, canary) {
		t.Fatalf("output file exists but lacks the canary: %q", out)
	}
	t.Logf("a workflow dev:exec action ran OUTSIDE any sandbox, in this test process, as uid %s",
		strings.TrimSpace(strings.SplitN(out, "\n", 2)[0]))
	t.Errorf("workflow action on system \"dev\" ran a shell command directly in the control-plane "+
		"process instead of inside a sandbox (contradicts orchestrator.go's own comment on "+
		"NoCredentials systems): output file %s contains %q", outFile, canary)
}

// TestSec21_..._control proves the test can see a command actually land in the
// file at all: running the same command directly (not through ActAs) must
// produce the same evidence. PASS = the detector works.
func TestSec21_WorkflowDevActionDoesNotRunInTheControlPlane_control(t *testing.T) {
	secTest(t)
	canary := newCanary("control")
	outFile := filepath.Join(t.TempDir(), "sec21-control.txt")
	cmd := "echo " + canary + " >> " + outFile
	if err := exec.Command("sh", "-c", cmd).Run(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(outFile)
	if err != nil || !strings.Contains(string(b), canary) {
		t.Fatalf("control broken: a direct shell command did not produce the expected file: %v, %q", err, string(b))
	}
}
