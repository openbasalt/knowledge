package signing

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
)

// Envelope is a signed object. The layout and the signed bytes follow the
// DSSE envelope (Dead Simple Signing Envelope, version 1): the signature
// covers the pre-authentication encoding of the payload type and the exact
// payload bytes, so no JSON canonicalization is needed and a payload can
// never be read as another type.
type Envelope struct {
	PayloadType string      `json:"payloadType"`
	Payload     string      `json:"payload"` // base64 (standard, padded)
	Signatures  []Signature `json:"signatures"`
}

// Signature is one signature over an envelope.
type Signature struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"` // base64 (standard, padded) of the 64-byte Ed25519 signature
}

// PAE is the DSSE pre-authentication encoding:
// "DSSEv1" SP LEN(type) SP type SP LEN(body) SP body.
func PAE(payloadType string, payload []byte) []byte {
	var b bytes.Buffer
	b.WriteString("DSSEv1 ")
	b.WriteString(strconv.Itoa(len(payloadType)))
	b.WriteByte(' ')
	b.WriteString(payloadType)
	b.WriteByte(' ')
	b.WriteString(strconv.Itoa(len(payload)))
	b.WriteByte(' ')
	b.Write(payload)
	return b.Bytes()
}

// Seal signs payload with every signer.
func Seal(payloadType string, payload []byte, signers ...*Signer) (*Envelope, error) {
	if len(signers) == 0 {
		return nil, errors.New("seal: no signer")
	}
	msg := PAE(payloadType, payload)
	env := &Envelope{PayloadType: payloadType, Payload: base64.StdEncoding.EncodeToString(payload)}
	for _, s := range signers {
		env.Signatures = append(env.Signatures, Signature{KeyID: s.KeyID(), Sig: base64.StdEncoding.EncodeToString(s.Sign(msg))})
	}
	return env, nil
}

// SealJSON marshals v and signs it.
func SealJSON(payloadType string, v any, signers ...*Signer) (*Envelope, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return Seal(payloadType, b, signers...)
}

// Digest is the content address of an envelope's payload:
// "sha256:" followed by the hex SHA-256 of the payload bytes.
func (e *Envelope) Digest() (string, error) {
	b, err := base64.StdEncoding.DecodeString(e.Payload)
	if err != nil {
		return "", fmt.Errorf("payload: %v", err)
	}
	return DigestBytes(b), nil
}

// DigestBytes returns "sha256:<hex>" of b.
func DigestBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// KeyLookup resolves a key id to a trusted public key, or reports false.
type KeyLookup func(keyid string) (ed25519.PublicKey, bool)

// ErrUnsigned is returned when an envelope has no valid signature from a
// trusted key.
var ErrUnsigned = errors.New("no valid signature from a trusted key")

// Open verifies the envelope and returns its payload. The payload type
// must equal want, and at least threshold distinct trusted keys must have
// signed it (signatures by unknown keys are ignored, not errors, so a key
// can be added before every client knows it). Nothing of the payload is
// returned unless the check passes.
func (e *Envelope) Open(want string, threshold int, lookup KeyLookup) ([]byte, []string, error) {
	if e == nil {
		return nil, nil, ErrUnsigned
	}
	if e.PayloadType != want {
		return nil, nil, fmt.Errorf("payload type %q: want %q", e.PayloadType, want)
	}
	if threshold < 1 {
		threshold = 1
	}
	payload, err := base64.StdEncoding.DecodeString(e.Payload)
	if err != nil {
		return nil, nil, fmt.Errorf("payload: %v", err)
	}
	msg := PAE(e.PayloadType, payload)
	seen := map[string]bool{}
	var good []string
	for _, s := range e.Signatures {
		if seen[s.KeyID] {
			continue
		}
		pub, ok := lookup(s.KeyID)
		if !ok {
			continue
		}
		sig, err := base64.StdEncoding.DecodeString(s.Sig)
		if err != nil || len(sig) != ed25519.SignatureSize {
			continue
		}
		if ed25519.Verify(pub, msg, sig) {
			seen[s.KeyID] = true
			good = append(good, s.KeyID)
		}
	}
	if len(good) < threshold {
		if len(good) == 0 {
			return nil, nil, ErrUnsigned
		}
		return nil, nil, fmt.Errorf("%d valid signatures, need %d", len(good), threshold)
	}
	return payload, good, nil
}

// ParseEnvelope decodes an envelope and rejects unknown fields.
func ParseEnvelope(b []byte) (*Envelope, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var e Envelope
	if err := dec.Decode(&e); err != nil {
		return nil, fmt.Errorf("envelope: %v", err)
	}
	if e.PayloadType == "" || e.Payload == "" {
		return nil, errors.New("envelope: missing payloadType or payload")
	}
	return &e, nil
}
