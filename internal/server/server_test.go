package server_test

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openbasalt/knowledge/client"
	"github.com/openbasalt/knowledge/internal/build"
	"github.com/openbasalt/knowledge/internal/server"
	"github.com/openbasalt/knowledge/internal/testkit"
	"github.com/openbasalt/knowledge/protocol"
	"github.com/openbasalt/knowledge/signing"
)

func newServer(t *testing.T, kit *testkit.Kit, log *slog.Logger, burst int) *server.Server {
	t.Helper()
	srv, err := server.New(server.Config{
		Namespaces: []*build.Namespace{kit.Loaded}, Online: kit.Online,
		Delegations: map[string]*signing.Envelope{kit.NS: kit.Delegation}, Trust: kit.Trust(t),
		Requests: burst, Period: time.Minute, Burst: burst, Logger: log,
	})
	if err != nil {
		t.Fatal(err)
	}
	return srv
}

// The access log never holds the query: no free text, no hardware id,
// no path with an entry id, no client address.
func TestLogsNoQuery(t *testing.T) {
	kit := testkit.New(t, "../../content/basalt", time.Now())
	logs := &lockedBuffer{}
	srv := newServer(t, kit, slog.New(slog.NewJSONHandler(logs, nil)), 100)
	ts := httptest.NewServer(srv)
	c, err := client.New(ts.URL, kit.Trust(t))
	if err != nil {
		t.Fatal(err)
	}
	secret := "maria-laptop secret phrase"
	_, err = c.Search(context.Background(), protocol.SearchRequest{Namespace: "basalt", Intent: "driver.install",
		Hardware: []protocol.HardwareID{{Bus: "pci", Vendor: "10de", Device: "1b81"}},
		FreeText: &protocol.FreeText{Text: secret, Consent: "question"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Entry(context.Background(), "basalt", "nvidia-legacy-580"); err != nil {
		t.Fatal(err)
	}
	ts.Close() // waits for the handlers, so every log line is written
	out := logs.String()
	for _, leak := range []string{"maria", "secret", "1b81", "10de", "nvidia-legacy-580", "127.0.0.1"} {
		if strings.Contains(out, leak) {
			t.Errorf("log holds %q:\n%s", leak, out)
		}
	}
	if !strings.Contains(out, `"route":"POST /kb/v0/{ns}/search"`) {
		t.Errorf("log lacks the route: %s", out)
	}
}

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func TestRateLimit(t *testing.T) {
	kit := testkit.New(t, "../../content/basalt", time.Now())
	srv := newServer(t, kit, nil, 3)
	ts := httptest.NewServer(srv)
	defer ts.Close()
	var last *http.Response
	for i := 0; i < 4; i++ {
		resp, err := http.Get(ts.URL + "/kb/v0/basalt/catalog.json")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		last = resp
	}
	if last.StatusCode != http.StatusTooManyRequests || last.Header.Get("Retry-After") == "" {
		t.Fatalf("4th request: %d, Retry-After %q", last.StatusCode, last.Header.Get("Retry-After"))
	}
	// Health stays outside the limit.
	resp, err := http.Get(ts.URL + "/healthz")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz: %v %v", resp, err)
	}
	resp.Body.Close()
}

func TestStartupChecks(t *testing.T) {
	kit := testkit.New(t, "../../content/basalt", time.Now())
	other, _ := signing.GenerateKey(nil)
	_, err := server.New(server.Config{Namespaces: []*build.Namespace{kit.Loaded}, Online: other,
		Delegations: map[string]*signing.Envelope{kit.NS: kit.Delegation}, Trust: kit.Trust(t)})
	if err == nil {
		t.Fatal("a delegation for another key was accepted")
	}
	_, err = server.New(server.Config{Namespaces: []*build.Namespace{kit.Loaded}, Online: kit.Online, Trust: kit.Trust(t)})
	if err == nil {
		t.Fatal("a namespace without delegation was accepted")
	}
	// A delegation signed by the online key itself is not a delegation.
	self, _ := signing.SealJSON(signing.TypeDelegation, signing.Delegation{Schema: signing.SchemaDelegation,
		Namespace: kit.NS, Key: kit.Online.Public(), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}, kit.Online)
	_, err = server.New(server.Config{Namespaces: []*build.Namespace{kit.Loaded}, Online: kit.Online,
		Delegations: map[string]*signing.Envelope{kit.NS: self}, Trust: kit.Trust(t)})
	if err == nil {
		t.Fatal("a self-signed delegation was accepted")
	}
}

func TestNamespaceMismatchAndNoCookies(t *testing.T) {
	kit := testkit.New(t, "../../content/basalt", time.Now())
	ts := httptest.NewServer(newServer(t, kit, nil, 100))
	defer ts.Close()
	body := `{"schema":"kb.search.request/v0","namespace":"fedora","intent":"x","nonce":"AAAAAAAAAAAAAAAAAAAAAA"}`
	resp, err := http.Post(ts.URL+"/kb/v0/basalt/search", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("namespace mismatch: %d", resp.StatusCode)
	}
	if len(resp.Header.Values("Set-Cookie")) > 0 {
		t.Fatal("cookie set")
	}
}

// Fetch copies a published namespace from a mirror; the copy verifies.
func TestFetch(t *testing.T) {
	kit := testkit.New(t, "../../content/basalt", time.Now())
	mirror := httptest.NewServer(http.StripPrefix("/kb/v0", http.FileServer(http.Dir(kit.Out))))
	defer mirror.Close()
	dir := t.TempDir()
	if err := server.Fetch(context.Background(), mirror.URL, "basalt", dir); err != nil {
		t.Fatal(err)
	}
	n, err := build.LoadNamespace(dir+"/basalt", kit.Trust(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(n.Entries) != len(kit.Loaded.Entries) {
		t.Fatalf("%d entries fetched", len(n.Entries))
	}
}
