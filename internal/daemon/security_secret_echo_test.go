package daemon

// Security case 1 — a brokered secret must not come back to the model.
//
// actionproxy.go says substituteSecrets "keeps a secret ... out of the model's
// own context": the model writes {{secret:key}}, the daemon substitutes the
// value locally right before execution. But the substitution applies to ANY
// string parameter of ANY action, including dev:exec's `cmd`, and the result
// of the action goes back to the model verbatim (actionProxy.run wraps `data`
// unchanged). So `echo {{secret:key}}` prints the value into the model's
// context. This test asserts the secure behaviour: it FAILS while that holds.
//
// Mock only: a fake canary, no real credential, the real dev plugin running a
// harmless echo. Gated like the other security cases: COVEY_SECTEST=1.

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	// The dev plugin registers itself with the target registry; coveyd pulls it
	// in through plugins_bundled.go, the daemon's own tests do not.
	_ "github.com/benjaminLedel/covey-plugin-pack/dev"
)

func secTest(t *testing.T) {
	t.Helper()
	if os.Getenv("COVEY_SECTEST") != "1" {
		t.Skip("security case: set COVEY_SECTEST=1 to run")
	}
}

// secProxy builds an action proxy whose secret broker returns canary for
// gitlab_token and whose credential cache already holds an (empty) credential
// for dev, so execute() needs no WebSocket round trip.
func secProxy(t *testing.T, canary string) *actionProxy {
	t.Helper()
	c := &Client{
		homeDir:      t.TempDir(),
		creds:        map[string]InjectCredentials{"dev": {Granted: true, TTLSecs: 3600}},
		credsFetched: map[string]time.Time{"dev": time.Now()},
	}
	return &actionProxy{
		client: c,
		taskID: "sec-task-1",
		fetchSecret: func(_ context.Context, key, _ string) (InjectSecret, error) {
			if key != "gitlab_token" {
				return InjectSecret{}, fmt.Errorf("secret %q not granted", key)
			}
			return InjectSecret{Key: key, Granted: true, Value: canary}, nil
		},
	}
}

// modelSees is what the runtime (and so the model) receives for an action: the
// same {"status":"ok","data":...} object run() builds from execute()'s result.
func modelSees(t *testing.T, p *actionProxy, params string) string {
	t.Helper()
	data, err := p.execute(context.Background(), "dev", "exec", json.RawMessage(params))
	if err != nil {
		t.Fatalf("dev:exec failed: %v", err)
	}
	b, _ := json.Marshal(map[string]any{"status": "ok", "data": data})
	return string(b)
}

// TestSec01_SecretIsNotReturnedToTheModel — the case. FAIL = reproduces.
func TestSec01_SecretIsNotReturnedToTheModel(t *testing.T) {
	secTest(t)
	canary := "CANARY-GITLAB-" + strings.ToUpper(fmt.Sprintf("%x", time.Now().UnixNano()))[:8]
	p := secProxy(t, canary)

	seen := modelSees(t, p, `{"cmd":"echo {{secret:gitlab_token}}"}`)
	if strings.Contains(seen, canary) {
		t.Errorf("the brokered secret came back to the model through dev:exec output "+
			"(actionproxy.go substituteSecrets + run): %s", seen)
	}
}

// TestSec01_SecretIsNotReturnedToTheModel_control proves the detector can see
// a canary in a dev:exec result at all: a literal canary in the command must
// show up in what the model receives. PASS = the detector works.
func TestSec01_SecretIsNotReturnedToTheModel_control(t *testing.T) {
	secTest(t)
	canary := "CANARY-CONTROL-" + strings.ToUpper(fmt.Sprintf("%x", time.Now().UnixNano()))[:8]
	p := secProxy(t, "unused")

	seen := modelSees(t, p, fmt.Sprintf(`{"cmd":"echo %s"}`, canary))
	if !strings.Contains(seen, canary) {
		t.Fatalf("control broken: a literal canary echoed by dev:exec is not visible in the result: %s", seen)
	}
}
