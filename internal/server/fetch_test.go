package server_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openbasalt/knowledge/internal/build"
	"github.com/openbasalt/knowledge/internal/server"
	"github.com/openbasalt/knowledge/internal/testkit"
	"github.com/openbasalt/knowledge/protocol"
	"github.com/openbasalt/knowledge/signing"
)

// mirror serves the kit's build output, with some files replaced.
func mirror(t *testing.T, kit *testkit.Kit, override map[string][]byte) *httptest.Server {
	t.Helper()
	files := http.StripPrefix("/kb/v"+protocol.Version, http.FileServer(http.Dir(kit.Out)))
	prefix := "/kb/v" + protocol.Version + "/" + kit.NS + "/"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if b, ok := override[strings.TrimPrefix(r.URL.Path, prefix)]; ok {
			_, _ = w.Write(b)
			return
		}
		// Any other request outside the published tree is answered too,
		// as a hostile mirror would.
		if !strings.HasPrefix(r.URL.Path, prefix) {
			_, _ = w.Write([]byte(`{"pwned":true}`))
			return
		}
		files.ServeHTTP(w, r)
	}))
	t.Cleanup(ts.Close)
	return ts
}

func readCatalog(t *testing.T, kit *testkit.Kit) protocol.Catalog {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(kit.Dir, "catalog.json"))
	if err != nil {
		t.Fatal(err)
	}
	env, err := signing.ParseEnvelope(b)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		t.Fatal(err)
	}
	var cat protocol.Catalog
	if err := json.Unmarshal(raw, &cat); err != nil {
		t.Fatal(err)
	}
	return cat
}

func seal(t *testing.T, typ string, v any, s *signing.Signer) []byte {
	t.Helper()
	env, err := signing.SealJSON(typ, v, s)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// listTree returns every path under dir (relative), for "nothing left
// behind" checks.
func listTree(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if p != dir {
			rel, _ := filepath.Rel(dir, p)
			out = append(out, rel)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// A catalog version with dot segments (signed even by the real publisher)
// is refused before any request for it is made, and nothing is written
// outside the data directory, or inside it.
func TestFetchRefusesTraversalInVersion(t *testing.T) {
	kit := testkit.New(t, "../../content/basalt", time.Now())
	top := t.TempDir()
	data := filepath.Join(top, "data")
	cat := readCatalog(t, kit)
	// From <data>/<ns>/packs/<id>-1, four levels up is top: the old code
	// wrote top/escaped.json.
	evil := "1/../../../../escaped"
	cat.Packs[0].Version = evil
	cat.Packs[0].Path = protocol.PackPath(cat.Packs[0].ID, evil)
	ts := mirror(t, kit, map[string][]byte{
		"catalog.json":    seal(t, protocol.TypeCatalog, cat, kit.Publisher),
		cat.Packs[0].Path: []byte(`{"pwned":true}`),
	})
	err := server.Fetch(context.Background(), ts.URL, kit.NS, data, kit.Trust(t))
	if err == nil {
		t.Fatal("traversal in the pack version was accepted")
	}
	if got := listTree(t, top); len(got) != 1 || got[0] != "data" {
		t.Fatalf("files left behind: %v", got)
	}
}

// Paths that are absolute, climb out, or are not clean are refused by
// the confinement check itself.
func TestFetchLocalPath(t *testing.T) {
	for _, rel := range []string{"/etc/x.json", "../x.json", "packs/../../x.json", "packs//x.json",
		"./x.json", "", `packs\..\x.json`, "x\x00.json"} {
		if err := server.CheckMirrorPath(rel); err == nil {
			t.Errorf("%q accepted", rel)
		}
	}
	for _, rel := range []string{"catalog.json", "keyring/1.json", "packs/a-b-1.2.json", "entries/x-y.json"} {
		if err := server.CheckMirrorPath(rel); err != nil {
			t.Errorf("%q refused: %v", rel, err)
		}
	}
}

// A symbolic link at the namespace path that points outside the data
// directory is replaced, not written through.
func TestFetchSymlinkInData(t *testing.T) {
	kit := testkit.New(t, "../../content/basalt", time.Now())
	top := t.TempDir()
	data := filepath.Join(top, "data")
	outside := filepath.Join(top, "outside")
	for _, d := range []string{data, outside} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(outside, filepath.Join(data, kit.NS)); err != nil {
		t.Fatal(err)
	}
	ts := mirror(t, kit, nil)
	if err := server.Fetch(context.Background(), ts.URL, kit.NS, data, kit.Trust(t)); err != nil {
		t.Fatal(err)
	}
	if got := listTree(t, outside); len(got) != 0 {
		t.Fatalf("written through the link: %v", got)
	}
	fi, err := os.Lstat(filepath.Join(data, kit.NS))
	if err != nil || !fi.IsDir() {
		t.Fatalf("namespace is not a plain directory: %v %v", fi, err)
	}
	if _, err := build.LoadNamespace(filepath.Join(data, kit.NS), kit.Trust(t)); err != nil {
		t.Fatal(err)
	}
	for _, p := range listTree(t, data) {
		if strings.HasPrefix(p, ".fetch-") {
			t.Fatalf("staging left behind: %s", p)
		}
	}
}

// A pack that the trusted publisher did not sign fails verification; the
// staged files are removed and a copy fetched before stays untouched.
func TestFetchUnsignedPack(t *testing.T) {
	kit := testkit.New(t, "../../content/basalt", time.Now())
	data := t.TempDir()
	good := mirror(t, kit, nil)
	if err := server.Fetch(context.Background(), good.URL, kit.NS, data, kit.Trust(t)); err != nil {
		t.Fatal(err)
	}
	before := listTree(t, data)

	// Re-sign the first pack with a key nobody trusts, then give the
	// catalog the matching digest and size under the real publisher, so
	// only the pack signature is wrong.
	cat := readCatalog(t, kit)
	cp := cat.Packs[0]
	pb, err := os.ReadFile(filepath.Join(kit.Dir, filepath.FromSlash(cp.Path)))
	if err != nil {
		t.Fatal(err)
	}
	env, err := signing.ParseEnvelope(pb)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		t.Fatal(err)
	}
	var p protocol.Pack
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatal(err)
	}
	stranger, err := signing.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	bad := seal(t, protocol.TypePack, p, stranger)
	cat.Packs[0].Digest = signing.DigestBytes(bad)
	cat.Packs[0].Size = int64(len(bad))
	evil := mirror(t, kit, map[string][]byte{
		"catalog.json": seal(t, protocol.TypeCatalog, cat, kit.Publisher),
		cp.Path:        bad,
	})
	if err := server.Fetch(context.Background(), evil.URL, kit.NS, data, kit.Trust(t)); err == nil {
		t.Fatal("a pack with an untrusted signature was accepted")
	}
	after := listTree(t, data)
	if strings.Join(before, "\n") != strings.Join(after, "\n") {
		t.Fatalf("data changed after a failed fetch:\nbefore %v\nafter %v", before, after)
	}
	if _, err := build.LoadNamespace(filepath.Join(data, kit.NS), kit.Trust(t)); err != nil {
		t.Fatalf("earlier copy no longer verifies: %v", err)
	}

	// Into an empty data directory, nothing at all is left.
	empty := t.TempDir()
	if err := server.Fetch(context.Background(), evil.URL, kit.NS, empty, kit.Trust(t)); err == nil {
		t.Fatal("a pack with an untrusted signature was accepted")
	}
	if got := listTree(t, empty); len(got) != 0 {
		t.Fatalf("files left behind: %v", got)
	}
}
