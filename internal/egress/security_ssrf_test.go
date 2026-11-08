package egress

// Security case 3 — an allowlisted hostname that resolves to a loopback/
// private address must not let the sandbox reach it.
//
// Allowlist.Allows and the proxy's handleConnect/handleHTTP only ever compare
// the HOST STRING from the allowlist against the HOST STRING in the request;
// nothing on this path resolves the name and checks the resulting IP before
// dialling (handleConnect calls net.DialTimeout("tcp", host, ...) directly,
// handleHTTP hands the request straight to http.DefaultTransport.RoundTrip).
// So once an org has allowlisted some hostname for a legitimate reason (a
// partner API, a webhook target), anything that makes that name resolve to an
// internal address — DNS rebinding, a compromised/expired domain, a
// misconfigured record — reaches that internal address with no further check.
// "localhost" stands in here for such a name: the code treats it exactly like
// any other allowlisted hostname, and the only reason it is reliable in a test
// without relying on live/controlled DNS is that every Unix resolver answers
// it with 127.0.0.1 locally. The vulnerability is the missing IP check, not
// anything special about "localhost" itself.
//
// Mock only: a local TCP listener stands in for the internal-only service;
// no real credentials, no real target systems. Gated: COVEY_SECTEST=1.

import (
	"bufio"
	"encoding/base64"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
)

func secTest(t *testing.T) {
	t.Helper()
	if os.Getenv("COVEY_SECTEST") != "1" {
		t.Skip("security case: set COVEY_SECTEST=1 to run")
	}
}

// sec03Listener starts a TCP listener bound to loopback that stands in for an
// internal-only service (e.g. a metadata endpoint, an internal admin panel)
// and answers every connection with a fixed banner so the test can prove the
// tunnel really carried bytes, not just that CONNECT returned 200.
func sec03Listener(t *testing.T) (hostPort string, close func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = c.Write([]byte("INTERNAL-SERVICE-REACHED"))
			}()
		}
	}()
	return ln.Addr().String(), func() { ln.Close() }
}

// sec03Connect issues a raw CONNECT through the proxy and returns the status
// code plus (on 200) the hijacked connection.
func sec03Connect(t *testing.T, proxyAddr, agent, token, target string) (int, net.Conn) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	req := "CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n" +
		"Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(agent+":"+token)) + "\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		conn.Close()
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		conn.Close()
		return resp.StatusCode, nil
	}
	return resp.StatusCode, conn
}

// TestSec03_AllowlistedHostnameResolvingToLoopbackIsRefused — the case. FAIL =
// a hostname on the agent's allowlist that resolves to loopback let the tunnel
// through to the internal-only listener.
func TestSec03_AllowlistedHostnameResolvingToLoopbackIsRefused(t *testing.T) {
	secTest(t)
	internal, closeInternal := sec03Listener(t)
	defer closeInternal()
	_, internalPort, _ := net.SplitHostPort(internal)

	// The org allowlisted "localhost" the way it might allowlist any ordinary
	// external hostname (a partner API domain); nothing distinguishes it to
	// the proxy's Allows() check.
	res := &stubResolver{agent: uuid.New(), token: "s3cret", allow: NewAllowlist([]string{"localhost"})}
	p := New(res, nil)
	addr, err := p.Start("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	code, conn := sec03Connect(t, addr, res.agent.String(), "s3cret", "localhost:"+internalPort)
	if code == http.StatusOK {
		buf := make([]byte, 64)
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, _ := conn.Read(buf)
		conn.Close()
		t.Errorf("an allowlisted hostname (\"localhost\") that resolves to loopback reached an "+
			"internal-only listener through the egress proxy (CONNECT status %d, read %q) — "+
			"the proxy never checks the resolved IP before dialling (egress/proxy.go handleConnect)",
			code, buf[:n])
		return
	}
	// Any non-200 here is fine for this test's purpose (it means the proxy
	// did refuse it) but 403 is the specific, correct refusal.
	if code != http.StatusForbidden {
		t.Errorf("expected 403 (egress denied), got %d", code)
	}
}

// _control: the SAME request against the SAME internal listener, but with
// "localhost" removed from the allowlist, must still be refused — isolating
// the vulnerable condition to "the hostname happens to be on the allowlist",
// not "the Allows() gate is broken outright" (that would make this test
// vacuous). Also proves the harness can observe a genuine refusal.
func TestSec03_AllowlistedHostnameResolvingToLoopbackIsRefused_control(t *testing.T) {
	secTest(t)
	internal, closeInternal := sec03Listener(t)
	defer closeInternal()
	_, internalPort, _ := net.SplitHostPort(internal)

	res := &stubResolver{agent: uuid.New(), token: "s3cret", allow: NewAllowlist([]string{"some-other-partner.example"})}
	p := New(res, nil)
	addr, err := p.Start("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	code, conn := sec03Connect(t, addr, res.agent.String(), "s3cret", "localhost:"+internalPort)
	if code != http.StatusForbidden {
		if conn != nil {
			conn.Close()
		}
		t.Fatalf("control broken: \"localhost\" is not on this agent's allowlist, so CONNECT must be "+
			"refused, got %d", code)
	}
}
