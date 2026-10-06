// Package client is the Go client of the knowledge protocol. It trusts
// only the keyrings it was given (pinned) and the rotations they sign,
// verifies every object it receives (entries and packs by the namespace's
// publisher keys, search responses and errors by the server's delegated
// online key), and refuses anything unsigned, mismatched or stale. The
// transport is not trusted: HTTPS protects privacy, signatures protect
// content.
package client

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/openbasalt/knowledge/protocol"
	"github.com/openbasalt/knowledge/signing"
)

// WellKnown is the discovery path.
const WellKnown = "/.well-known/openbasalt-knowledge"

// MaxResponseBytes bounds every response body.
const MaxResponseBytes = 8 << 20

// Client talks to one server or static mirror.
type Client struct {
	base    *url.URL
	HTTP    *http.Client
	Trust   *signing.Trust
	MaxSkew time.Duration // allowed clock difference for issued_at (default 5 minutes)
	Now     func() time.Time
	// RateRetries is how many times a request answered 429 is retried
	// after its Retry-After, when that wait is at most RateMaxWait. Zero
	// (the default) returns the rate_limited error at once, which suits
	// interactive use; batch tools set it.
	RateRetries int
	RateMaxWait time.Duration

	mu          sync.Mutex
	delegations map[string]*signing.Delegation
}

// New returns a client for base (https, or http to a loopback address).
func New(base string, trust *signing.Trust) (*Client, error) {
	u, err := url.Parse(strings.TrimRight(base, "/"))
	if err != nil {
		return nil, err
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && loopback(u.Hostname())) {
		return nil, fmt.Errorf("base URL must be https (http only to a loopback address)")
	}
	if trust == nil {
		return nil, errors.New("client needs pinned keyrings")
	}
	return &Client{base: u, HTTP: &http.Client{Timeout: 20 * time.Second}, Trust: trust,
		MaxSkew: 5 * time.Minute, delegations: map[string]*signing.Delegation{}}, nil
}

func loopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (c *Client) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// ProtocolError is an error response. Verified is true only when the
// error was signed by the server's delegated key; an unverified error is
// a transport failure and says nothing about the content.
type ProtocolError struct {
	Status   int
	Code     string
	Message  string
	Retry    int
	Verified bool
}

func (e *ProtocolError) Error() string {
	v := "unverified"
	if e.Verified {
		v = "signed"
	}
	return fmt.Sprintf("server error %d %s (%s): %s", e.Status, e.Code, v, e.Message)
}

func (c *Client) do(ctx context.Context, method, path string, body []byte) (int, []byte, error) {
	for attempt := 0; ; attempt++ {
		status, retry, b, err := c.once(ctx, method, path, body)
		if err != nil || status != http.StatusTooManyRequests || attempt >= c.RateRetries ||
			retry < 0 || time.Duration(retry)*time.Second > c.RateMaxWait {
			return status, b, err
		}
		select {
		case <-ctx.Done():
			return 0, nil, ctx.Err()
		case <-time.After(time.Duration(retry)*time.Second + 100*time.Millisecond):
		}
	}
}

func (c *Client) once(ctx context.Context, method, path string, body []byte) (int, int, []byte, error) {
	u := *c.base
	u.Path = strings.TrimRight(u.Path, "/") + path
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), rd)
	if err != nil {
		return 0, 0, nil, err
	}
	req.Header.Set("Accept", protocol.MediaType)
	if body != nil {
		req.Header.Set("Content-Type", protocol.MediaType)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return 0, 0, nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponseBytes+1))
	if err != nil {
		return 0, 0, nil, err
	}
	if len(b) > MaxResponseBytes {
		return 0, 0, nil, errors.New("response too large")
	}
	retry := -1
	if v, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil {
		retry = v
	}
	return resp.StatusCode, retry, b, nil
}

// VerifyError turns a non-200 body into a ProtocolError, verified when the
// namespace's delegation is known and the signature checks.
func (c *Client) VerifyError(status int, b []byte, ns string) error {
	pe := &ProtocolError{Status: status, Code: "transport", Message: http.StatusText(status)}
	env, err := signing.ParseEnvelope(b)
	if err != nil {
		return pe
	}
	c.mu.Lock()
	d := c.delegations[ns]
	if d == nil {
		// Errors are signed by the server's one online key; any of its
		// delegations names it.
		for _, other := range c.delegations {
			d = other
			break
		}
	}
	c.mu.Unlock()
	if d == nil {
		return pe
	}
	payload, err := d.OpenOnline(env, protocol.TypeError)
	if err != nil {
		return pe
	}
	var e protocol.Error
	if protocol.DecodeStrict(payload, &e) != nil || e.Schema != protocol.SchemaError {
		return pe
	}
	return &ProtocolError{Status: status, Code: e.Code, Message: e.Message, Retry: e.RetryAfter, Verified: true}
}

// Discover fetches and verifies the server's discovery document and keeps
// the delegations of the trusted namespaces it lists. The server must
// speak protocol version 0.
func (c *Client) Discover(ctx context.Context) (*protocol.Discovery, error) {
	status, b, err := c.do(ctx, http.MethodGet, WellKnown, nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, c.VerifyError(status, b, "")
	}
	env, err := signing.ParseEnvelope(b)
	if err != nil {
		return nil, err
	}
	// The delegations inside are verified on their own (publisher keys)
	// before the document's signature is checked with the key they name.
	raw, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return nil, err
	}
	var unverified protocol.Discovery
	if err := json.Unmarshal(raw, &unverified); err != nil {
		return nil, fmt.Errorf("discovery: %v", err)
	}
	found := map[string]*signing.Delegation{}
	for _, n := range unverified.Namespaces {
		if _, trusted := c.Trust.Keyring(n.Name); !trusted || n.Delegation == nil {
			continue
		}
		d, err := c.Trust.OpenDelegation(n.Delegation, n.Name)
		if err != nil {
			return nil, fmt.Errorf("discovery: namespace %s: %v", n.Name, err)
		}
		found[n.Name] = d
	}
	if len(found) == 0 {
		return nil, errors.New("discovery: the server serves no namespace this client trusts")
	}
	var verified []byte
	for _, d := range found {
		if verified, err = d.OpenOnline(env, protocol.TypeDiscovery); err != nil {
			return nil, fmt.Errorf("discovery: %v", err)
		}
	}
	var disc protocol.Discovery
	if err := protocol.DecodeStrict(verified, &disc); err != nil {
		return nil, fmt.Errorf("discovery: %v", err)
	}
	if disc.Schema != protocol.SchemaDiscovery {
		return nil, fmt.Errorf("discovery schema %q", disc.Schema)
	}
	if err := disc.Privacy.Validate(); err != nil {
		return nil, fmt.Errorf("discovery: %v", err)
	}
	if !slices.Contains(disc.Versions, protocol.Version) {
		return nil, fmt.Errorf("server speaks protocol versions %v, this client speaks %s", disc.Versions, protocol.Version)
	}
	if err := c.fresh(disc.IssuedAt); err != nil {
		return nil, fmt.Errorf("discovery: %v", err)
	}
	c.mu.Lock()
	for ns, d := range found {
		c.delegations[ns] = d
	}
	c.mu.Unlock()
	return &disc, nil
}

func (c *Client) fresh(t time.Time) error {
	now := c.now()
	if t.Before(now.Add(-c.MaxSkew)) || t.After(now.Add(c.MaxSkew)) {
		return fmt.Errorf("issued at %s, too far from the local clock", t.Format(time.RFC3339))
	}
	return nil
}

func (c *Client) delegation(ctx context.Context, ns string) (*signing.Delegation, error) {
	c.mu.Lock()
	d := c.delegations[ns]
	c.mu.Unlock()
	if d != nil && c.now().Before(d.NotAfter) {
		return d, nil
	}
	if _, err := c.Discover(ctx); err != nil {
		return nil, err
	}
	c.mu.Lock()
	d = c.delegations[ns]
	c.mu.Unlock()
	if d == nil {
		return nil, fmt.Errorf("the server has no valid delegation for namespace %s", ns)
	}
	return d, nil
}

// Hit is a verified search result.
type Hit struct {
	Entry   *protocol.Entry
	Digest  string
	Score   float64
	Pack    string
	Matched []string
}

// Results is a verified search response.
type Results struct {
	Hits   []Hit
	Packs  []protocol.PackRef
	Bundle protocol.BundleRef
}

// NewNonce returns 16 random bytes, base64url without padding.
func NewNonce() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// Search sends a structured query and returns only verified results. The
// request is validated before it leaves the machine; schema and nonce are
// filled in.
func (c *Client) Search(ctx context.Context, req protocol.SearchRequest) (*Results, error) {
	req.Schema = protocol.SchemaRequest
	req.Nonce = NewNonce()
	if err := req.Validate(); err != nil {
		return nil, err
	}
	d, err := c.delegation(ctx, req.Namespace)
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	status, b, err := c.do(ctx, http.MethodPost, "/kb/v"+protocol.Version+"/"+req.Namespace+"/search", body)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, c.VerifyError(status, b, req.Namespace)
	}
	env, err := signing.ParseEnvelope(b)
	if err != nil {
		return nil, err
	}
	payload, err := d.OpenOnline(env, protocol.TypeSearch)
	if err != nil {
		return nil, fmt.Errorf("search response: %v", err)
	}
	var resp protocol.SearchResponse
	if err := protocol.DecodeStrict(payload, &resp); err != nil {
		return nil, fmt.Errorf("search response: %v", err)
	}
	if resp.Schema != protocol.SchemaResponse || resp.Namespace != req.Namespace {
		return nil, errors.New("search response: wrong schema or namespace")
	}
	if resp.Nonce != req.Nonce || resp.RequestDigest != signing.DigestBytes(body) {
		return nil, errors.New("search response: not an answer to this request (nonce or request digest)")
	}
	if err := c.fresh(resp.IssuedAt); err != nil {
		return nil, fmt.Errorf("search response: %v", err)
	}
	out := &Results{Packs: resp.Packs, Bundle: resp.Bundle}
	for _, r := range resp.Results {
		e, digest, err := protocol.OpenEntry(c.Trust, r.Entry, req.Namespace)
		if err != nil {
			return nil, fmt.Errorf("result %s: %v", r.ID, err)
		}
		if e.ID != r.ID || digest != r.Digest || e.Pack != r.Pack {
			return nil, fmt.Errorf("result %s: does not match its signed entry", r.ID)
		}
		out.Hits = append(out.Hits, Hit{Entry: e, Digest: digest, Score: r.Score, Pack: r.Pack, Matched: r.Matched})
	}
	return out, nil
}

func (c *Client) getEnvelope(ctx context.Context, ns, rel string) (*signing.Envelope, []byte, error) {
	status, b, err := c.do(ctx, http.MethodGet, "/kb/v"+protocol.Version+"/"+ns+"/"+rel, nil)
	if err != nil {
		return nil, nil, err
	}
	if status != http.StatusOK {
		return nil, nil, c.VerifyError(status, b, ns)
	}
	env, err := signing.ParseEnvelope(b)
	return env, b, err
}

// Entry fetches and verifies one entry. It works against a static mirror
// too (no discovery needed).
func (c *Client) Entry(ctx context.Context, ns, id string) (*protocol.Entry, error) {
	if !protocol.ValidID(id) {
		return nil, fmt.Errorf("entry id %q is not valid", id)
	}
	env, _, err := c.getEnvelope(ctx, ns, protocol.EntryPath(id))
	if err != nil {
		return nil, err
	}
	e, _, err := protocol.OpenEntry(c.Trust, env, ns)
	if err != nil {
		return nil, err
	}
	if e.ID != id {
		return nil, fmt.Errorf("asked for entry %s, got %s", id, e.ID)
	}
	return e, nil
}

// Catalog fetches and verifies the namespace's pack catalog.
func (c *Client) Catalog(ctx context.Context, ns string) (*protocol.Catalog, error) {
	env, _, err := c.getEnvelope(ctx, ns, "catalog.json")
	if err != nil {
		return nil, err
	}
	cat, _, err := protocol.OpenCatalog(c.Trust, env, ns)
	return cat, err
}

// Pack downloads one pack listed in a verified catalog and checks its
// size, digest, signature and every entry. It returns the file bytes so
// the caller can keep the pack for offline use.
func (c *Client) Pack(ctx context.Context, ns string, cp protocol.CatalogPack) (*protocol.Pack, []*protocol.Entry, []byte, error) {
	env, raw, err := c.getEnvelope(ctx, ns, cp.Path)
	if err != nil {
		return nil, nil, nil, err
	}
	if int64(len(raw)) != cp.Size || signing.DigestBytes(raw) != cp.Digest {
		return nil, nil, nil, fmt.Errorf("pack %s: size or digest does not match the catalog", cp.ID)
	}
	p, entries, err := protocol.OpenPack(c.Trust, env, ns)
	if err != nil {
		return nil, nil, nil, err
	}
	if p.ID != cp.ID || p.Version != cp.Version {
		return nil, nil, nil, fmt.Errorf("pack %s %s: the file holds %s %s", cp.ID, cp.Version, p.ID, p.Version)
	}
	return p, entries, raw, nil
}

// UpdateKeyring follows key rotations of a namespace: it fetches the
// latest keyring and, when it is newer, every version in between, each
// verified by the one before (see signing.Rotate).
func (c *Client) UpdateKeyring(ctx context.Context, ns string) (*signing.Keyring, error) {
	cur, ok := c.Trust.Keyring(ns)
	if !ok {
		return nil, fmt.Errorf("namespace %s is not trusted", ns)
	}
	latestEnv, _, err := c.getEnvelope(ctx, ns, "keyring.json")
	if err != nil {
		return nil, err
	}
	raw, err := base64.StdEncoding.DecodeString(latestEnv.Payload)
	if err != nil {
		return nil, err
	}
	var latest signing.Keyring
	if err := json.Unmarshal(raw, &latest); err != nil {
		return nil, err
	}
	if latest.Version <= cur.Version {
		return cur, nil
	}
	if latest.Version-cur.Version > 1000 {
		return nil, errors.New("keyring: implausible version jump")
	}
	for v := cur.Version + 1; v <= latest.Version; v++ {
		env, _, err := c.getEnvelope(ctx, ns, protocol.KeyringPath(v))
		if err != nil {
			return nil, fmt.Errorf("keyring %d: %v", v, err)
		}
		if _, err := c.Trust.Update(env); err != nil {
			return nil, err
		}
	}
	k, _ := c.Trust.Keyring(ns)
	return k, nil
}
