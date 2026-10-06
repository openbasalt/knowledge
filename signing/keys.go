// Package signing holds the cryptography of the knowledge protocol: Ed25519
// keys, signed envelopes, namespace keyrings with key rotation, and the
// delegation that lets a server's online key sign search responses for a
// namespace. It uses only the Go standard library, so any client can verify
// what a server sends without a third-party module.
package signing

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
)

// Key file types.
const (
	TypePrivate = "ed25519-private"
	TypePublic  = "ed25519-public"
)

var reKeyID = regexp.MustCompile(`^[0-9a-f]{32}$`)

// KeyID is the identifier of a public key: the first 16 bytes of the
// SHA-256 of the raw 32-byte key, in lower case hex.
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:16])
}

// ValidKeyID reports whether s has the shape of a key id.
func ValidKeyID(s string) bool { return reKeyID.MatchString(s) }

// PublicKey is a public key as it appears in key files and keyrings.
type PublicKey struct {
	Type   string `json:"type"`
	KeyID  string `json:"keyid"`
	Public string `json:"public"` // base64 (standard, padded) of the 32 raw bytes
}

// Key returns the raw key after checking the type, length and key id.
func (p PublicKey) Key() (ed25519.PublicKey, error) {
	if p.Type != TypePublic {
		return nil, fmt.Errorf("key type %q: want %q", p.Type, TypePublic)
	}
	raw, err := base64.StdEncoding.DecodeString(p.Public)
	if err != nil {
		return nil, fmt.Errorf("public key: %v", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("public key: %d bytes, want %d", len(raw), ed25519.PublicKeySize)
	}
	pub := ed25519.PublicKey(raw)
	if KeyID(pub) != p.KeyID {
		return nil, fmt.Errorf("public key: key id %s does not match the key", p.KeyID)
	}
	return pub, nil
}

// NewPublicKey wraps a raw key.
func NewPublicKey(pub ed25519.PublicKey) PublicKey {
	return PublicKey{Type: TypePublic, KeyID: KeyID(pub), Public: base64.StdEncoding.EncodeToString(pub)}
}

// privateFile is the on-disk form of a private key. The seed is the only
// secret; the public key is stored too so a damaged file is detected.
type privateFile struct {
	Type   string `json:"type"`
	KeyID  string `json:"keyid"`
	Seed   string `json:"seed"`
	Public string `json:"public"`
}

// Signer is a private key that can sign envelopes.
type Signer struct {
	id   string
	priv ed25519.PrivateKey
}

// KeyID returns the signer's key id.
func (s *Signer) KeyID() string { return s.id }

// Public returns the signer's public key.
func (s *Signer) Public() PublicKey { return NewPublicKey(s.priv.Public().(ed25519.PublicKey)) }

// Sign signs msg with the private key.
func (s *Signer) Sign(msg []byte) []byte { return ed25519.Sign(s.priv, msg) }

// GenerateKey creates a new key from r (crypto/rand when nil).
func GenerateKey(r io.Reader) (*Signer, error) {
	if r == nil {
		r = rand.Reader
	}
	_, priv, err := ed25519.GenerateKey(r)
	if err != nil {
		return nil, err
	}
	return &Signer{id: KeyID(priv.Public().(ed25519.PublicKey)), priv: priv}, nil
}

// MarshalPrivate encodes the key for a key file. The caller writes it with
// mode 0600.
func (s *Signer) MarshalPrivate() ([]byte, error) {
	pub := s.priv.Public().(ed25519.PublicKey)
	return json.MarshalIndent(privateFile{
		Type:   TypePrivate,
		KeyID:  s.id,
		Seed:   base64.StdEncoding.EncodeToString(s.priv.Seed()),
		Public: base64.StdEncoding.EncodeToString(pub),
	}, "", "  ")
}

// ParsePrivate decodes a private key file.
func ParsePrivate(b []byte) (*Signer, error) {
	var f privateFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("private key: %v", err)
	}
	if f.Type != TypePrivate {
		return nil, fmt.Errorf("private key type %q: want %q", f.Type, TypePrivate)
	}
	seed, err := base64.StdEncoding.DecodeString(f.Seed)
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("private key: bad seed")
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	if base64.StdEncoding.EncodeToString(pub) != f.Public || KeyID(pub) != f.KeyID {
		return nil, errors.New("private key: public key or key id does not match the seed")
	}
	return &Signer{id: f.KeyID, priv: priv}, nil
}

// LoadPrivate reads a private key file. It refuses files that other users
// may read, so a key is not used from a careless location.
func LoadPrivate(path string) (*Signer, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if st.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("private key %s: mode %v, want 0600 or stricter", path, st.Mode().Perm())
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParsePrivate(b)
}

// ParsePublic decodes a public key file.
func ParsePublic(b []byte) (PublicKey, error) {
	var p PublicKey
	if err := json.Unmarshal(b, &p); err != nil {
		return p, fmt.Errorf("public key: %v", err)
	}
	if _, err := p.Key(); err != nil {
		return p, err
	}
	return p, nil
}
