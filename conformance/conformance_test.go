package conformance_test

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/openbasalt/knowledge/conformance"
	"github.com/openbasalt/knowledge/internal/build"
	"github.com/openbasalt/knowledge/internal/server"
	"github.com/openbasalt/knowledge/internal/testkit"
	"github.com/openbasalt/knowledge/signing"
)

// TestServerConformance runs the whole suite against kbd's handler built
// from the seed content with keys made for this run.
func TestServerConformance(t *testing.T) {
	kit := testkit.New(t, "../content/basalt", time.Now())
	srv, err := server.New(server.Config{
		Namespaces:  []*build.Namespace{kit.Loaded},
		Online:      kit.Online,
		Delegations: map[string]*signing.Envelope{kit.NS: kit.Delegation},
		Trust:       kit.Trust(t),
		Requests:    1000, Period: time.Minute, Burst: 1000,
	})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv)
	defer ts.Close()
	results, err := conformance.Run(context.Background(), ts.URL, kit.Trust(t), conformance.BasaltFixture())
	if err != nil {
		t.Fatal(err)
	}
	if len(results) < 15 {
		t.Fatalf("only %d checks ran", len(results))
	}
	for _, r := range results {
		t.Logf("%-6s pass=%-5v %s", r.Level, r.Pass, r.ID)
		if !r.Pass {
			t.Errorf("%s %s: %s", r.Level, r.ID, r.Detail)
		}
	}
}
