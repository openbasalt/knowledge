package signing

import (
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func mustKey(t *testing.T) *Signer {
	t.Helper()
	k, err := GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func ring(ns string, version int, roots []*Signer, pubs []*Signer, revoked ...string) *Keyring {
	k := &Keyring{Schema: SchemaKeyring, Namespace: ns, Version: version, Threshold: 1, Revoked: revoked}
	for _, s := range roots {
		k.Keys = append(k.Keys, KeyringKey{PublicKey: s.Public(), Roles: []string{RoleRoot}})
	}
	for _, s := range pubs {
		k.Keys = append(k.Keys, KeyringKey{PublicKey: s.Public(), Roles: []string{RolePublisher}})
	}
	return k
}

func TestEnvelopeRoundTrip(t *testing.T) {
	k := mustKey(t)
	env, err := Seal("application/x-test", []byte(`{"a":1}`), k)
	if err != nil {
		t.Fatal(err)
	}
	trusted := KeyLookup(func(id string) (ed25519.PublicKey, bool) {
		pub, err := k.Public().Key()
		return pub, err == nil && id == k.KeyID()
	})
	b, ids, err := env.Open("application/x-test", 1, trusted)
	if err != nil || string(b) != `{"a":1}` || len(ids) != 1 {
		t.Fatalf("open: %q %v %v", b, ids, err)
	}
	// Wrong payload type.
	if _, _, err := env.Open("application/x-other", 1, trusted); err == nil {
		t.Fatal("wrong payload type accepted")
	}
	// Tampered payload.
	bad := *env
	bad.Payload = base64.StdEncoding.EncodeToString([]byte(`{"a":2}`))
	if _, _, err := bad.Open("application/x-test", 1, trusted); err != ErrUnsigned {
		t.Fatalf("tampered payload: %v", err)
	}
	// Unknown key only.
	other := mustKey(t)
	env2, _ := Seal("application/x-test", []byte("x"), other)
	if _, _, err := env2.Open("application/x-test", 1, trusted); err != ErrUnsigned {
		t.Fatalf("unknown key: %v", err)
	}
	// Threshold of two with one trusted key and a duplicate signature.
	env3, _ := Seal("application/x-test", []byte("x"), k, k)
	if _, _, err := env3.Open("application/x-test", 2, trusted); err == nil {
		t.Fatal("duplicate signature counted twice")
	}
	// Strict parsing.
	if _, err := ParseEnvelope([]byte(`{"payloadType":"a","payload":"eA==","signatures":[],"extra":1}`)); err == nil {
		t.Fatal("unknown field accepted")
	}
}

func TestPrivateKeyFile(t *testing.T) {
	k := mustKey(t)
	b, err := k.MarshalPrivate()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "k.json")
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPrivate(p); err == nil || !strings.Contains(err.Error(), "mode") {
		t.Fatalf("world-readable key accepted: %v", err)
	}
	if err := os.Chmod(p, 0o600); err != nil {
		t.Fatal(err)
	}
	k2, err := LoadPrivate(p)
	if err != nil || k2.KeyID() != k.KeyID() {
		t.Fatalf("load: %v", err)
	}
	// A seed that does not match the stored public key is refused.
	other := mustKey(t)
	ob, _ := other.MarshalPrivate()
	mixed := strings.Replace(string(ob), other.Public().Public, k.Public().Public, 1)
	if _, err := ParsePrivate([]byte(mixed)); err == nil {
		t.Fatal("mismatched key file accepted")
	}
}

func TestKeyringRotation(t *testing.T) {
	root1, pub1 := mustKey(t), mustKey(t)
	v1env, err := SealJSON(TypeKeyring, ring("basalt", 1, []*Signer{root1}, []*Signer{pub1}), root1)
	if err != nil {
		t.Fatal(err)
	}
	tr := NewTrust()
	if _, err := tr.Pin(v1env); err != nil {
		t.Fatal(err)
	}
	// v2 rotates the root and the publisher and revokes the old publisher.
	root2, pub2 := mustKey(t), mustKey(t)
	v2 := ring("basalt", 2, []*Signer{root2}, []*Signer{pub2}, pub1.KeyID())
	onlyNew, _ := SealJSON(TypeKeyring, v2, root2)
	if _, err := tr.Update(onlyNew); err == nil {
		t.Fatal("rotation without the old root accepted")
	}
	onlyOld, _ := SealJSON(TypeKeyring, v2, root1)
	if _, err := tr.Update(onlyOld); err == nil {
		t.Fatal("rotation without the new root accepted")
	}
	both, _ := SealJSON(TypeKeyring, v2, root1, root2)
	k, err := tr.Update(both)
	if err != nil || k.Version != 2 {
		t.Fatalf("rotation: %v", err)
	}
	// Content by the revoked publisher is refused, by the new one accepted.
	old, _ := Seal("application/x-entry", []byte("e"), pub1)
	if _, err := tr.OpenPublisher(old, "basalt", "application/x-entry"); err == nil {
		t.Fatal("revoked publisher accepted")
	}
	cur, _ := Seal("application/x-entry", []byte("e"), pub2)
	if _, err := tr.OpenPublisher(cur, "basalt", "application/x-entry"); err != nil {
		t.Fatal(err)
	}
	// v3 must keep the revocation.
	v3 := ring("basalt", 3, []*Signer{root2}, []*Signer{pub2})
	v3env, _ := SealJSON(TypeKeyring, v3, root2)
	if _, err := tr.Update(v3env); err == nil {
		t.Fatal("dropped revocation accepted")
	}
	// A root key cannot sign entries.
	byRoot, _ := Seal("application/x-entry", []byte("e"), root2)
	if _, err := tr.OpenPublisher(byRoot, "basalt", "application/x-entry"); err == nil {
		t.Fatal("root key accepted as publisher")
	}
}

func TestDelegation(t *testing.T) {
	root, pub, online := mustKey(t), mustKey(t), mustKey(t)
	env, _ := SealJSON(TypeKeyring, ring("basalt", 1, []*Signer{root}, []*Signer{pub}), root)
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	tr := NewTrust()
	tr.Now = func() time.Time { return now }
	if _, err := tr.Pin(env); err != nil {
		t.Fatal(err)
	}
	mk := func(nb, na time.Time, by *Signer) *Envelope {
		e, _ := SealJSON(TypeDelegation, Delegation{Schema: SchemaDelegation, Namespace: "basalt", Key: online.Public(), NotBefore: nb, NotAfter: na}, by)
		return e
	}
	d, err := tr.OpenDelegation(mk(now.Add(-time.Hour), now.Add(24*time.Hour), pub), "basalt")
	if err != nil {
		t.Fatal(err)
	}
	resp, _ := Seal("application/x-resp", []byte("r"), online)
	if _, err := d.OpenOnline(resp, "application/x-resp"); err != nil {
		t.Fatal(err)
	}
	if _, err := d.OpenOnline(resp, "application/x-other"); err == nil {
		t.Fatal("wrong type accepted")
	}
	if _, err := tr.OpenDelegation(mk(now.Add(-48*time.Hour), now.Add(-time.Hour), pub), "basalt"); err == nil {
		t.Fatal("expired delegation accepted")
	}
	if _, err := tr.OpenDelegation(mk(now.Add(-time.Hour), now.Add(100*24*time.Hour), pub), "basalt"); err == nil {
		t.Fatal("too long delegation accepted")
	}
	if _, err := tr.OpenDelegation(mk(now.Add(-time.Hour), now.Add(time.Hour), online), "basalt"); err == nil {
		t.Fatal("self-signed delegation accepted")
	}
	if _, err := tr.OpenDelegation(mk(now.Add(-time.Hour), now.Add(time.Hour), pub), "fedora"); err == nil {
		t.Fatal("delegation for an untrusted namespace accepted")
	}
}
