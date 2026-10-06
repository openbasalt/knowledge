// Package testkit builds a signed namespace with keys made for one test
// run. No key it makes is ever written outside the test's temporary
// directory.
package testkit

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/openbasalt/knowledge/internal/build"
	"github.com/openbasalt/knowledge/internal/source"
	"github.com/openbasalt/knowledge/signing"
)

// Kit is a built namespace with its keys.
type Kit struct {
	Out        string // build output root
	Dir        string // <Out>/<ns>
	NS         string
	Root       *signing.Signer
	Publisher  *signing.Signer
	Online     *signing.Signer
	Keyring    *signing.Envelope
	TrustJSON  []byte
	Delegation *signing.Envelope
	Loaded     *build.Namespace
}

// Trust returns a fresh trust store with the kit's keyring pinned.
func (k *Kit) Trust(t testing.TB) *signing.Trust {
	t.Helper()
	tr, err := signing.ParseTrust(k.TrustJSON)
	if err != nil {
		t.Fatal(err)
	}
	return tr
}

func key(t testing.TB) *signing.Signer {
	t.Helper()
	s, err := signing.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// New builds contentDir with new keys and a delegation valid around now.
func New(t testing.TB, contentDir string, now time.Time) *Kit {
	t.Helper()
	src, err := source.Load(contentDir)
	if err != nil {
		t.Fatal(err)
	}
	k := &Kit{Out: t.TempDir(), NS: src.Namespace.Namespace, Root: key(t), Publisher: key(t), Online: key(t)}
	ring := signing.Keyring{Schema: signing.SchemaKeyring, Namespace: k.NS, Version: 1, Threshold: 1,
		Keys: []signing.KeyringKey{
			{PublicKey: k.Root.Public(), Roles: []string{signing.RoleRoot}},
			{PublicKey: k.Publisher.Public(), Roles: []string{signing.RolePublisher}},
		}}
	if k.Keyring, err = signing.SealJSON(signing.TypeKeyring, ring, k.Root); err != nil {
		t.Fatal(err)
	}
	if k.TrustJSON, err = json.Marshal(signing.TrustFile{Schema: signing.SchemaTrust, Keyrings: []*signing.Envelope{k.Keyring}}); err != nil {
		t.Fatal(err)
	}
	res, err := build.Build(src, build.Options{Out: k.Out, Version: "2026.10.5", Created: now.Add(-time.Hour),
		Signer: k.Publisher, Keyrings: []*signing.Envelope{k.Keyring}})
	if err != nil {
		t.Fatal(err)
	}
	k.Dir = res.Dir
	d := signing.Delegation{Schema: signing.SchemaDelegation, Namespace: k.NS, Key: k.Online.Public(),
		NotBefore: now.Add(-24 * time.Hour), NotAfter: now.Add(30 * 24 * time.Hour)}
	if k.Delegation, err = signing.SealJSON(signing.TypeDelegation, d, k.Publisher); err != nil {
		t.Fatal(err)
	}
	if k.Loaded, err = build.LoadNamespace(k.Dir, k.Trust(t)); err != nil {
		t.Fatal(err)
	}
	return k
}
