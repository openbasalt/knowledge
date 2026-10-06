package client_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/openbasalt/knowledge/client"
	"github.com/openbasalt/knowledge/internal/build"
	"github.com/openbasalt/knowledge/internal/server"
	"github.com/openbasalt/knowledge/internal/testkit"
	"github.com/openbasalt/knowledge/protocol"
	"github.com/openbasalt/knowledge/signing"
)

// tamper is a man in the middle: it lets the real server answer and then
// rewrites the body.
func tamper(h http.Handler, rewrite func(path string, body []byte) []byte) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		for k, v := range rec.Header() {
			w.Header()[k] = v
		}
		w.Header().Del("Content-Length")
		w.WriteHeader(rec.Code)
		_, _ = w.Write(rewrite(r.URL.Path, rec.Body.Bytes()))
	})
}

func setup(t *testing.T, rewrite func(string, []byte) []byte) (*testkit.Kit, *client.Client) {
	t.Helper()
	kit := testkit.New(t, "../content/basalt", time.Now())
	srv, err := server.New(server.Config{Namespaces: []*build.Namespace{kit.Loaded}, Online: kit.Online,
		Delegations: map[string]*signing.Envelope{kit.NS: kit.Delegation}, Trust: kit.Trust(t),
		Requests: 1000, Period: time.Minute, Burst: 1000})
	if err != nil {
		t.Fatal(err)
	}
	var h http.Handler = srv
	if rewrite != nil {
		h = tamper(srv, rewrite)
	}
	ts := httptest.NewServer(h)
	t.Cleanup(ts.Close)
	c, err := client.New(ts.URL, kit.Trust(t))
	if err != nil {
		t.Fatal(err)
	}
	return kit, c
}

var gtx = protocol.SearchRequest{Namespace: "basalt", Intent: "driver.install",
	Hardware: []protocol.HardwareID{{Bus: "pci", Vendor: "10de", Device: "1b81"}}}

func TestHonestServer(t *testing.T) {
	_, c := setup(t, nil)
	res, err := c.Search(context.Background(), gtx)
	if err != nil || len(res.Hits) == 0 || res.Hits[0].Entry.ID != "nvidia-legacy-580" {
		t.Fatalf("%v %v", res, err)
	}
	// A signed protocol error is reported as verified.
	_, err = c.Entry(context.Background(), "basalt", "no-such-entry")
	var pe *client.ProtocolError
	if !errors.As(err, &pe) || !pe.Verified || pe.Code != protocol.ErrNotFound {
		t.Fatalf("not found: %v", err)
	}
}

func reseal(body []byte, edit func(payload []byte) []byte) []byte {
	var env signing.Envelope
	if json.Unmarshal(body, &env) != nil {
		return body
	}
	p, _ := base64.StdEncoding.DecodeString(env.Payload)
	env.Payload = base64.StdEncoding.EncodeToString(edit(p))
	b, _ := json.Marshal(env)
	return b
}

func TestRefusesTampering(t *testing.T) {
	ctx := context.Background()
	cases := map[string]func(string, []byte) []byte{
		// The outer response is edited: its online signature breaks.
		"response edited": func(path string, b []byte) []byte {
			if !strings.HasSuffix(path, "/search") {
				return b
			}
			return reseal(b, func(p []byte) []byte { return bytes.Replace(p, []byte(`"score":`), []byte(`"score":9`), 1) })
		},
		// The signature is dropped altogether.
		"response unsigned": func(path string, b []byte) []byte {
			if !strings.HasSuffix(path, "/search") {
				return b
			}
			var env signing.Envelope
			_ = json.Unmarshal(b, &env)
			env.Signatures = nil
			out, _ := json.Marshal(env)
			return out
		},
		// Discovery is edited after signing (a weaker privacy promise).
		"discovery edited": func(path string, b []byte) []byte {
			if path != client.WellKnown {
				return b
			}
			return reseal(b, func(p []byte) []byte { return bytes.Replace(p, []byte(`"no-query-logging",`), nil, 1) })
		},
	}
	for name, rw := range cases {
		t.Run(name, func(t *testing.T) {
			_, c := setup(t, rw)
			if _, err := c.Search(ctx, gtx); err == nil {
				t.Fatal("tampered response accepted")
			}
		})
	}
	t.Run("entry edited", func(t *testing.T) {
		_, c := setup(t, func(path string, b []byte) []byte {
			if !strings.HasPrefix(path, "/kb/v0/basalt/entries/") {
				return b
			}
			return reseal(b, func(p []byte) []byte {
				return bytes.Replace(p, []byte(`"risk":"low"`), []byte(`"risk":"low","params":{"cmd":"rm -rf /"}`), 1)
			})
		})
		if _, err := c.Entry(ctx, "basalt", "journal-disk-usage"); err == nil {
			t.Fatal("edited entry accepted")
		}
	})
	t.Run("error unsigned", func(t *testing.T) {
		_, c := setup(t, func(path string, b []byte) []byte {
			if !strings.HasPrefix(path, "/kb/v0/basalt/entries/") {
				return b
			}
			return []byte(`{"payloadType":"application/vnd.openbasalt.knowledge.error+json","payload":"e30=","signatures":[]}`)
		})
		_, _ = c.Discover(ctx)
		_, err := c.Entry(ctx, "basalt", "no-such-entry")
		var pe *client.ProtocolError
		if !errors.As(err, &pe) || pe.Verified {
			t.Fatalf("unsigned error reported as verified: %v", err)
		}
	})
}

// A response replayed for another request (other nonce) is refused.
func TestRefusesReplay(t *testing.T) {
	var saved []byte
	_, c := setup(t, func(path string, b []byte) []byte {
		if !strings.HasSuffix(path, "/search") {
			return b
		}
		if saved == nil {
			saved = b
		}
		return saved
	})
	ctx := context.Background()
	if _, err := c.Search(ctx, gtx); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Search(ctx, gtx); err == nil {
		t.Fatal("replayed response accepted")
	}
}

// A stale response (clock skew) is refused.
func TestRefusesStale(t *testing.T) {
	_, c := setup(t, nil)
	c.Now = func() time.Time { return time.Now().Add(time.Hour) }
	if _, err := c.Search(context.Background(), gtx); err == nil {
		t.Fatal("stale response accepted")
	}
}

func TestBaseURL(t *testing.T) {
	tr := signing.NewTrust()
	for _, u := range []string{"http://example.org", "ftp://127.0.0.1"} {
		if _, err := client.New(u, tr); err == nil {
			t.Errorf("%s accepted", u)
		}
	}
	for _, u := range []string{"https://example.org", "http://127.0.0.1:8080", "http://localhost"} {
		if _, err := client.New(u, tr); err != nil {
			t.Errorf("%s: %v", u, err)
		}
	}
}

// Packs from a static mirror verify, and a corrupted pack is refused.
func TestStaticMirrorPack(t *testing.T) {
	kit := testkit.New(t, "../content/basalt", time.Now())
	corrupt := false
	fs := http.StripPrefix("/kb/v0", http.FileServer(http.Dir(kit.Out)))
	mirror := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if corrupt && strings.Contains(r.URL.Path, "/packs/") {
			rec := httptest.NewRecorder()
			fs.ServeHTTP(rec, r)
			b, _ := io.ReadAll(rec.Body)
			b[len(b)/2] ^= 0x01 // one bit flipped in transit or on the mirror's disk
			_, _ = w.Write(b)
			return
		}
		fs.ServeHTTP(w, r)
	}))
	defer mirror.Close()
	c, err := client.New(mirror.URL, kit.Trust(t))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	cat, err := c.Catalog(ctx, "basalt")
	if err != nil {
		t.Fatal(err)
	}
	for _, cp := range cat.Packs {
		if _, _, _, err := c.Pack(ctx, "basalt", cp); err != nil {
			t.Fatal(err)
		}
	}
	corrupt = true
	for _, cp := range cat.Packs {
		if cp.ID == "core" {
			if _, _, _, err := c.Pack(ctx, "basalt", cp); err == nil {
				t.Fatal("corrupted pack accepted")
			}
		}
	}
}

// Key rotation: the client follows a keyring signed by the old root.
func TestKeyRotation(t *testing.T) {
	kit := testkit.New(t, "../content/basalt", time.Now())
	root2, _ := signing.GenerateKey(nil)
	pub2, _ := signing.GenerateKey(nil)
	v2 := signing.Keyring{Schema: signing.SchemaKeyring, Namespace: "basalt", Version: 2, Threshold: 1,
		Keys: []signing.KeyringKey{{PublicKey: root2.Public(), Roles: []string{signing.RoleRoot}},
			{PublicKey: pub2.Public(), Roles: []string{signing.RolePublisher}}},
		Revoked: []string{kit.Publisher.KeyID()}}
	env2, err := signing.SealJSON(signing.TypeKeyring, v2, kit.Root, root2)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(env2)
	mux := http.NewServeMux()
	mux.HandleFunc("/kb/v0/basalt/keyring.json", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(b) })
	mux.HandleFunc("/kb/v0/basalt/keyring/2.json", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(b) })
	ts := httptest.NewServer(mux)
	defer ts.Close()
	tr := kit.Trust(t)
	c, _ := client.New(ts.URL, tr)
	k, err := c.UpdateKeyring(context.Background(), "basalt")
	if err != nil || k.Version != 2 {
		t.Fatalf("rotation: %v", err)
	}
	// Content signed by the revoked publisher no longer verifies.
	if _, _, err := protocol.OpenEntry(tr, kit.Loaded.Entries["journal-disk-usage"].Env, "basalt"); err == nil {
		t.Fatal("entry by a revoked key accepted")
	}
}
