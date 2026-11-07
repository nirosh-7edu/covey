package integration

// Helpers for the security cases (security_*_test.go).
//
// These tests assert the SECURE behaviour, so a failing test means the issue
// reproduces. They are skipped unless COVEY_SECTEST=1 — a case that currently
// fails must not turn the normal run red. Every case comes with a "_control"
// test that builds the known-vulnerable condition on purpose and asserts that
// the detector sees it; if a control fails, the detector is broken and the
// case's result means nothing.
//
// Mock only: no real credentials, no real target systems. A canary is a
// unique fake secret; after a run it is searched for in the database, in the
// files under the stack's home directory and in everything a sink received.

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
)

const secTestEnv = "COVEY_SECTEST"

// secTest skips the calling test unless the security cases are switched on.
func secTest(t *testing.T) {
	t.Helper()
	if os.Getenv(secTestEnv) != "1" {
		t.Skipf("security case: set %s=1 to run", secTestEnv)
	}
}

// newCanary returns a unique fake secret, e.g. CANARY-GITLAB-3F9A12BC.
func newCanary(label string) string {
	id := strings.ToUpper(strings.ReplaceAll(uuid.NewString(), "-", ""))[:8]
	return "CANARY-" + strings.ToUpper(label) + "-" + id
}

// sinkHit is one request a sink received.
type sinkHit struct {
	Method string
	Path   string
	Query  string
	Header http.Header
	Body   string
}

func (h sinkHit) String() string {
	return fmt.Sprintf("%s %s?%s", h.Method, h.Path, h.Query)
}

// contains reports whether the needle appears anywhere in the request.
func (h sinkHit) contains(needle string) bool {
	if strings.Contains(h.Path, needle) || strings.Contains(h.Query, needle) || strings.Contains(h.Body, needle) {
		return true
	}
	for k, vs := range h.Header {
		if strings.Contains(k, needle) {
			return true
		}
		for _, v := range vs {
			if strings.Contains(v, needle) {
				return true
			}
		}
	}
	return false
}

// sink is a local HTTP server that records everything it receives and answers
// 200 — the stand-in for "an attacker's host" and for fake target systems.
type sink struct {
	*httptest.Server
	mu   sync.Mutex
	hits []sinkHit
}

func newSink(t *testing.T) *sink {
	t.Helper()
	k := &sink{}
	k.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		k.mu.Lock()
		k.hits = append(k.hits, sinkHit{
			Method: r.Method, Path: r.URL.Path, Query: r.URL.RawQuery,
			Header: r.Header.Clone(), Body: string(body),
		})
		k.mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(k.Close)
	return k
}

// Hits returns a copy of what the sink has received so far.
func (k *sink) Hits() []sinkHit {
	k.mu.Lock()
	defer k.mu.Unlock()
	return append([]sinkHit(nil), k.hits...)
}

// saw returns the requests that carried the needle.
func (k *sink) saw(needle string) []sinkHit {
	var out []sinkHit
	for _, h := range k.Hits() {
		if h.contains(needle) {
			out = append(out, h)
		}
	}
	return out
}

// dbHits lists "table.column" for every text-like column of the stack's
// database that holds the needle. Encrypted columns (bytea) cannot match,
// which is the point: a canary found in a plain column was stored in the clear.
func (s *stack) dbHits(t *testing.T, needle string) []string {
	t.Helper()
	ctx := context.Background()
	rows, err := s.pool.Query(ctx, `SELECT table_name, column_name FROM information_schema.columns
		WHERE table_schema = 'public' AND data_type IN ('text','character varying','jsonb','json')
		AND table_name IN (SELECT table_name FROM information_schema.tables
			WHERE table_schema = 'public' AND table_type = 'BASE TABLE')`)
	if err != nil {
		t.Fatal(err)
	}
	type col struct{ table, column string }
	var cols []col
	for rows.Next() {
		var c col
		if err := rows.Scan(&c.table, &c.column); err != nil {
			t.Fatal(err)
		}
		cols = append(cols, c)
	}
	rows.Close()

	var hits []string
	for _, c := range cols {
		q := fmt.Sprintf(`SELECT count(*) FROM %q WHERE %q::text LIKE '%%' || $1 || '%%'`, c.table, c.column)
		var n int
		if err := s.pool.QueryRow(ctx, q, needle).Scan(&n); err != nil {
			continue // a column the cast cannot read is not a place a canary can sit
		}
		if n > 0 {
			hits = append(hits, c.table+"."+c.column)
		}
	}
	return hits
}

// fileHits lists the files under root (the stack's home directory, recordings
// and the like) whose content holds the needle.
func fileHits(root, needle string) []string {
	var hits []string
	_ = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if info, err := d.Info(); err != nil || info.Size() > 4<<20 || !info.Mode().IsRegular() {
			return nil
		}
		if b, err := os.ReadFile(p); err == nil && strings.Contains(string(b), needle) {
			hits = append(hits, "file:"+p)
		}
		return nil
	})
	return hits
}

// leaks searches every place the stack keeps or sends data for the needle and
// returns one line per place that holds it. Empty means: found nowhere.
func (s *stack) leaks(t *testing.T, needle string, sinks ...*sink) []string {
	t.Helper()
	var out []string
	for _, h := range s.dbHits(t, needle) {
		out = append(out, "db:"+h)
	}
	if s.homeBase != "" {
		out = append(out, fileHits(s.homeBase, needle)...)
	}
	for _, k := range sinks {
		for _, h := range k.saw(needle) {
			out = append(out, "sink:"+h.String())
		}
	}
	return out
}

// TestSec00_HarnessDetectsACanary is the control for the helpers themselves:
// a canary planted in a column, a file and a sink request must be found, and a
// different canary must not. If this fails, no other security result counts.
func TestSec00_HarnessDetectsACanary(t *testing.T) {
	secTest(t)
	s := newStack(t)
	ctx := context.Background()

	planted := newCanary("probe")
	other := newCanary("never-planted")

	if _, err := s.pool.Exec(ctx, `CREATE TABLE sec_probe (v text)`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.pool.Exec(ctx, `INSERT INTO sec_probe (v) VALUES ($1)`, "x "+planted+" y"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.homeBase, "probe.txt"), []byte(planted), 0o600); err != nil {
		t.Fatal(err)
	}
	k := newSink(t)
	req, _ := http.NewRequest(http.MethodGet, k.URL+"/x", nil)
	req.Header.Set("Authorization", "Bearer "+planted)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	got := strings.Join(s.leaks(t, planted, k), "\n")
	for _, want := range []string{"db:sec_probe.v", "file:", "sink:GET /x"} {
		if !strings.Contains(got, want) {
			t.Errorf("planted canary not found in %q; got:\n%s", want, got)
		}
	}
	if miss := s.leaks(t, other, k); len(miss) != 0 {
		t.Errorf("a canary that was never planted was reported: %v", miss)
	}
}
