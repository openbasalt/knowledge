package signing

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"slices"
	"sync"
	"time"
)

// Payload types of the objects this package signs and verifies.
const (
	TypeKeyring    = "application/vnd.openbasalt.knowledge.keyring+json"
	TypeDelegation = "application/vnd.openbasalt.knowledge.delegation+json"
)

// Schemas of the payloads.
const (
	SchemaKeyring    = "kb.keyring/v0"
	SchemaDelegation = "kb.delegation/v0"
	SchemaTrust      = "kb.trust/v0"
)

// Key roles in a keyring.
const (
	RoleRoot      = "root"      // signs the next version of the keyring
	RolePublisher = "publisher" // signs entries, packs, catalogs and delegations
)

// MaxDelegation is the longest lifetime a client accepts for an online key.
const MaxDelegation = 90 * 24 * time.Hour

var reNamespace = regexp.MustCompile(`^[a-z][a-z0-9-]{1,31}$`)

// ValidNamespace reports whether s is a valid namespace name.
func ValidNamespace(s string) bool { return reNamespace.MatchString(s) }

// KeyringKey is a key listed in a keyring, with its roles and validity.
type KeyringKey struct {
	PublicKey
	Roles     []string   `json:"roles"`
	NotBefore *time.Time `json:"not_before,omitempty"`
	NotAfter  *time.Time `json:"not_after,omitempty"`
}

// validAt reports whether the key is inside its validity window.
func (k KeyringKey) validAt(t time.Time) bool {
	if k.NotBefore != nil && t.Before(*k.NotBefore) {
		return false
	}
	if k.NotAfter != nil && t.After(*k.NotAfter) {
		return false
	}
	return true
}

// Keyring lists the keys of one namespace. Version N+1 must be signed by a
// threshold of the root keys of version N and of its own root keys, so a
// client that pinned any version can follow every rotation after it.
type Keyring struct {
	Schema    string       `json:"schema"`
	Namespace string       `json:"namespace"`
	Version   int          `json:"version"`
	Threshold int          `json:"threshold"`
	Keys      []KeyringKey `json:"keys"`
	Revoked   []string     `json:"revoked,omitempty"`
}

// Validate checks the keyring's own consistency.
func (k *Keyring) Validate() error {
	if k.Schema != SchemaKeyring {
		return fmt.Errorf("keyring schema %q: want %q", k.Schema, SchemaKeyring)
	}
	if !ValidNamespace(k.Namespace) {
		return fmt.Errorf("keyring namespace %q is not valid", k.Namespace)
	}
	if k.Version < 1 {
		return errors.New("keyring version must be 1 or more")
	}
	if k.Threshold < 1 {
		return errors.New("keyring threshold must be 1 or more")
	}
	roots, pubs := 0, 0
	seen := map[string]bool{}
	for _, key := range k.Keys {
		if _, err := key.Key(); err != nil {
			return err
		}
		if seen[key.KeyID] {
			return fmt.Errorf("key %s listed twice", key.KeyID)
		}
		seen[key.KeyID] = true
		if slices.Contains(k.Revoked, key.KeyID) {
			return fmt.Errorf("key %s is listed and revoked", key.KeyID)
		}
		for _, r := range key.Roles {
			switch r {
			case RoleRoot:
				roots++
			case RolePublisher:
				pubs++
			default:
				return fmt.Errorf("key %s: unknown role %q", key.KeyID, r)
			}
		}
	}
	if roots < k.Threshold {
		return fmt.Errorf("keyring has %d root keys, threshold %d", roots, k.Threshold)
	}
	if pubs == 0 {
		return errors.New("keyring has no publisher key")
	}
	return nil
}

// lookup returns a KeyLookup over the keys with a role, valid at t.
func (k *Keyring) lookup(role string, t time.Time) KeyLookup {
	return func(id string) (ed25519.PublicKey, bool) {
		if slices.Contains(k.Revoked, id) {
			return nil, false
		}
		for _, key := range k.Keys {
			if key.KeyID != id || !slices.Contains(key.Roles, role) || !key.validAt(t) {
				continue
			}
			pub, err := key.Key()
			if err != nil {
				return nil, false
			}
			return pub, true
		}
		return nil, false
	}
}

// decodeStrict decodes JSON and rejects unknown fields.
func decodeStrict(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

// peekKeyring decodes a keyring payload without checking signatures.
func peekKeyring(env *Envelope) (*Keyring, error) {
	if env.PayloadType != TypeKeyring {
		return nil, fmt.Errorf("payload type %q: want %q", env.PayloadType, TypeKeyring)
	}
	b, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return nil, err
	}
	var k Keyring
	if err := decodeStrict(b, &k); err != nil {
		return nil, fmt.Errorf("keyring: %v", err)
	}
	if err := k.Validate(); err != nil {
		return nil, err
	}
	return &k, nil
}

// OpenPinned accepts a keyring the client pins (shipped with the system or
// configured by an administrator). Trust comes from where the file is,
// not from its signatures; the self-signature by its own root keys is
// still checked so a damaged or edited file is refused.
func OpenPinned(env *Envelope, now time.Time) (*Keyring, error) {
	k, err := peekKeyring(env)
	if err != nil {
		return nil, err
	}
	if _, _, err := env.Open(TypeKeyring, k.Threshold, k.lookup(RoleRoot, now)); err != nil {
		return nil, fmt.Errorf("keyring %s v%d self-signature: %v", k.Namespace, k.Version, err)
	}
	return k, nil
}

// Rotate verifies next against the current keyring and returns it. The
// next version must be newer, for the same namespace, and signed by a
// threshold of the current root keys and of its own root keys. A key the
// current keyring revoked can never return.
func Rotate(cur *Keyring, env *Envelope, now time.Time) (*Keyring, error) {
	next, err := peekKeyring(env)
	if err != nil {
		return nil, err
	}
	if next.Namespace != cur.Namespace {
		return nil, fmt.Errorf("keyring namespace %q: want %q", next.Namespace, cur.Namespace)
	}
	if next.Version <= cur.Version {
		return nil, fmt.Errorf("keyring version %d is not newer than %d", next.Version, cur.Version)
	}
	for _, id := range cur.Revoked {
		if !slices.Contains(next.Revoked, id) {
			return nil, fmt.Errorf("keyring v%d drops revoked key %s", next.Version, id)
		}
	}
	if _, _, err := env.Open(TypeKeyring, cur.Threshold, cur.lookup(RoleRoot, now)); err != nil {
		return nil, fmt.Errorf("keyring v%d by the v%d root keys: %v", next.Version, cur.Version, err)
	}
	if _, _, err := env.Open(TypeKeyring, next.Threshold, next.lookup(RoleRoot, now)); err != nil {
		return nil, fmt.Errorf("keyring v%d by its own root keys: %v", next.Version, err)
	}
	return next, nil
}

// Delegation lets an online key sign dynamic responses (search results,
// discovery, errors) for a namespace. It is signed by a publisher key and
// short lived. The online key can never sign entries, packs or catalogs.
type Delegation struct {
	Schema    string    `json:"schema"`
	Namespace string    `json:"namespace"`
	Key       PublicKey `json:"key"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
}

// Trust holds the verified keyrings a client or server trusts, by
// namespace. It is safe for concurrent use.
type Trust struct {
	mu    sync.RWMutex
	rings map[string]*Keyring
	Now   func() time.Time
}

// NewTrust returns an empty trust store.
func NewTrust() *Trust { return &Trust{rings: map[string]*Keyring{}} }

func (t *Trust) now() time.Time {
	if t.Now != nil {
		return t.Now()
	}
	return time.Now()
}

// Pin adds a pinned keyring (see OpenPinned).
func (t *Trust) Pin(env *Envelope) (*Keyring, error) {
	k, err := OpenPinned(env, t.now())
	if err != nil {
		return nil, err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if old, ok := t.rings[k.Namespace]; ok && old.Version >= k.Version {
		return old, nil
	}
	t.rings[k.Namespace] = k
	return k, nil
}

// Update follows a rotation for the envelope's namespace (see Rotate).
// An envelope that is not newer is ignored.
func (t *Trust) Update(env *Envelope) (*Keyring, error) {
	peek, err := peekKeyring(env)
	if err != nil {
		return nil, err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	cur, ok := t.rings[peek.Namespace]
	if !ok {
		return nil, fmt.Errorf("namespace %q is not trusted", peek.Namespace)
	}
	if peek.Version <= cur.Version {
		return cur, nil
	}
	next, err := Rotate(cur, env, t.now())
	if err != nil {
		return nil, err
	}
	t.rings[next.Namespace] = next
	return next, nil
}

// Keyring returns the current keyring of a namespace.
func (t *Trust) Keyring(ns string) (*Keyring, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	k, ok := t.rings[ns]
	return k, ok
}

// Namespaces lists the trusted namespaces.
func (t *Trust) Namespaces() []string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	var out []string
	for ns := range t.rings {
		out = append(out, ns)
	}
	slices.Sort(out)
	return out
}

// OpenPublisher verifies an envelope signed by a publisher key of ns.
func (t *Trust) OpenPublisher(env *Envelope, ns, payloadType string) ([]byte, error) {
	k, ok := t.Keyring(ns)
	if !ok {
		return nil, fmt.Errorf("namespace %q is not trusted", ns)
	}
	b, _, err := env.Open(payloadType, 1, k.lookup(RolePublisher, t.now()))
	return b, err
}

// OpenDelegation verifies a delegation for ns and returns it when it is
// valid now and not longer than MaxDelegation.
func (t *Trust) OpenDelegation(env *Envelope, ns string) (*Delegation, error) {
	b, err := t.OpenPublisher(env, ns, TypeDelegation)
	if err != nil {
		return nil, fmt.Errorf("delegation: %v", err)
	}
	var d Delegation
	if err := decodeStrict(b, &d); err != nil {
		return nil, fmt.Errorf("delegation: %v", err)
	}
	if d.Schema != SchemaDelegation || d.Namespace != ns {
		return nil, fmt.Errorf("delegation: schema %q namespace %q", d.Schema, d.Namespace)
	}
	if _, err := d.Key.Key(); err != nil {
		return nil, fmt.Errorf("delegation: %v", err)
	}
	if d.NotAfter.Sub(d.NotBefore) > MaxDelegation {
		return nil, errors.New("delegation: lifetime longer than allowed")
	}
	now := t.now()
	if now.Before(d.NotBefore) || now.After(d.NotAfter) {
		return nil, errors.New("delegation: not valid now")
	}
	return &d, nil
}

// OpenOnline verifies an envelope signed by the delegated online key.
func (d *Delegation) OpenOnline(env *Envelope, payloadType string) ([]byte, error) {
	pub, err := d.Key.Key()
	if err != nil {
		return nil, err
	}
	b, _, err := env.Open(payloadType, 1, func(id string) (ed25519.PublicKey, bool) {
		return pub, id == d.Key.KeyID
	})
	return b, err
}

// TrustFile is the on-disk list of pinned keyrings.
type TrustFile struct {
	Schema   string      `json:"schema"`
	Keyrings []*Envelope `json:"keyrings"`
}

// LoadTrust reads a trust file and pins every keyring in it.
func LoadTrust(path string) (*Trust, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseTrust(b)
}

// ParseTrust decodes a trust file and pins every keyring in it.
func ParseTrust(b []byte) (*Trust, error) {
	var f TrustFile
	if err := decodeStrict(b, &f); err != nil {
		return nil, fmt.Errorf("trust file: %v", err)
	}
	if f.Schema != SchemaTrust {
		return nil, fmt.Errorf("trust file schema %q: want %q", f.Schema, SchemaTrust)
	}
	t := NewTrust()
	for _, env := range f.Keyrings {
		if _, err := t.Pin(env); err != nil {
			return nil, err
		}
	}
	if len(t.rings) == 0 {
		return nil, errors.New("trust file lists no keyring")
	}
	return t, nil
}
