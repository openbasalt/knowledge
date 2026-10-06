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
	"github.com/openbasalt/knowledge/protocol"
	"github.com/openbasalt/knowledge/signing"
)

// quaveLike is a hosting statement like the reference deployment's: an
// ingress that keeps access logs for 30 days, without request bodies.
func quaveLike() protocol.Hosting {
	yes, no, days := true, false, 30
	return protocol.Hosting{Declared: true, Provider: "Quave ONE", AccessLogs: &yes, RetentionDays: &days,
		Fields: []string{"ip", "time", "method", "path", "status", "size"}, QueryBodyLogged: &no}
}

func runSuite(t *testing.T, hosting protocol.Hosting) []conformance.Result {
	t.Helper()
	kit := testkit.New(t, "../content/basalt", time.Now())
	srv, err := server.New(server.Config{
		Namespaces:  []*build.Namespace{kit.Loaded},
		Online:      kit.Online,
		Delegations: map[string]*signing.Envelope{kit.NS: kit.Delegation},
		Trust:       kit.Trust(t),
		Requests:    1000, Period: time.Minute, Burst: 1000,
		Hosting: hosting,
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
	return results
}

// TestServerConformance runs the whole suite against kbd's handler built
// from the seed content with keys made for this run.
func TestServerConformance(t *testing.T) {
	for _, r := range runSuite(t, quaveLike()) {
		t.Logf("%-6s pass=%-5v %s", r.Level, r.Pass, r.ID)
		if !r.Pass {
			t.Errorf("%s %s: %s", r.Level, r.ID, r.Detail)
		}
	}
}

// An operator that declares nothing about its host still conforms, but
// the suite reports the missing statement.
func TestUndeclaredHosting(t *testing.T) {
	for _, r := range runSuite(t, protocol.Hosting{}) {
		switch {
		case r.ID == "discovery.hosting_declared" && r.Pass:
			t.Error("an undeclared hosting layer passed discovery.hosting_declared")
		case r.ID != "discovery.hosting_declared" && !r.Pass:
			t.Errorf("%s %s: %s", r.Level, r.ID, r.Detail)
		}
	}
}
