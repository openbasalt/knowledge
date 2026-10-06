// Package conformance checks that a server speaks the knowledge protocol
// v0 as docs/protocol.md and docs/conformance.md define it. It talks to
// the server only over HTTP, so it works against any implementation, and
// it validates every payload against the published JSON schemas.
//
// The checks need a fixture: a namespace the client trusts, a query that
// must find a known entry and pack, and a query that must not.
package conformance

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/openbasalt/knowledge/client"
	"github.com/openbasalt/knowledge/protocol"
	"github.com/openbasalt/knowledge/schemas"
	"github.com/openbasalt/knowledge/signing"
)

// Level of a check.
type Level string

// Levels, as in RFC 2119.
const (
	Must   Level = "MUST"
	Should Level = "SHOULD"
)

// Result of one check.
type Result struct {
	ID     string `json:"id"`
	Level  Level  `json:"level"`
	Pass   bool   `json:"pass"`
	Detail string `json:"detail,omitempty"`
}

// Fixture describes the content the server is expected to hold.
type Fixture struct {
	Namespace   string
	Match       protocol.SearchRequest // must return ExpectEntry and suggest ExpectPack
	NoMatch     protocol.SearchRequest // must not return ExpectEntry
	ExpectEntry string
	ExpectPack  string
}

// BasaltFixture fits the seed content of this repository: a GTX 1070 must
// find the NVIDIA 580 legacy guide, an RTX 4060 must not.
func BasaltFixture() Fixture {
	q := func(dev string) protocol.SearchRequest {
		return protocol.SearchRequest{Namespace: "basalt", Distro: "basalt", Intent: "driver.install", Component: "nvidia",
			Hardware: []protocol.HardwareID{{Bus: "pci", Vendor: "10de", Device: dev}}, Lang: "pt-BR"}
	}
	return Fixture{Namespace: "basalt", Match: q("1b81"), NoMatch: q("2882"),
		ExpectEntry: "nvidia-legacy-580", ExpectPack: "nvidia-legacy-580"}
}

// Validator validates payloads against the protocol's JSON schemas.
type Validator struct {
	schemas map[string]*jsonschema.Schema
}

// NewValidator compiles the embedded schemas.
func NewValidator() (*Validator, error) {
	c := jsonschema.NewCompiler()
	files, err := fs.Glob(schemas.FS, "*.schema.json")
	if err != nil {
		return nil, err
	}
	for _, f := range files {
		b, err := schemas.FS.ReadFile(f)
		if err != nil {
			return nil, err
		}
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
		if err != nil {
			return nil, fmt.Errorf("%s: %v", f, err)
		}
		if err := c.AddResource(schemas.Base+f, doc); err != nil {
			return nil, err
		}
	}
	v := &Validator{schemas: map[string]*jsonschema.Schema{}}
	for _, f := range files {
		s, err := c.Compile(schemas.Base + f)
		if err != nil {
			return nil, fmt.Errorf("%s: %v", f, err)
		}
		v.schemas[strings.TrimSuffix(f, ".schema.json")] = s
	}
	return v, nil
}

// Validate checks JSON bytes against a schema by name (entry, pack,
// catalog, search-request, search-response, discovery, error, envelope,
// keyring, delegation).
func (v *Validator) Validate(name string, b []byte) error {
	s := v.schemas[name]
	if s == nil {
		return fmt.Errorf("no schema %q", name)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
	if err != nil {
		return err
	}
	return s.Validate(doc)
}

// ValidateEnvelope checks the envelope and its payload's schema.
func (v *Validator) ValidateEnvelope(name string, raw []byte) error {
	if err := v.Validate("envelope", raw); err != nil {
		return fmt.Errorf("envelope: %v", err)
	}
	env, err := signing.ParseEnvelope(raw)
	if err != nil {
		return err
	}
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return err
	}
	return v.Validate(name, payload)
}

type runner struct {
	base    string
	http    *http.Client
	cl      *client.Client
	trust   *signing.Trust
	val     *Validator
	fx      Fixture
	results []Result
	disc    *protocol.Discovery
}

func (r *runner) check(id string, level Level, f func() error) {
	err := f()
	res := Result{ID: id, Level: level, Pass: err == nil}
	if err != nil {
		res.Detail = err.Error()
	}
	r.results = append(r.results, res)
}

// raw sends a request. A 429 with a short Retry-After is waited out and
// retried (a conforming server limits the suite like any client); other
// answers are returned as they are.
func (r *runner) raw(ctx context.Context, method, path, ctype string, body []byte, hdr map[string]string) (*http.Response, []byte, error) {
	for attempt := 0; ; attempt++ {
		resp, b, err := r.once(ctx, method, path, ctype, body, hdr)
		if err != nil || resp.StatusCode != http.StatusTooManyRequests || attempt == 5 {
			return resp, b, err
		}
		wait, perr := strconv.Atoi(resp.Header.Get("Retry-After"))
		if perr != nil || wait < 0 || wait > 60 {
			return resp, b, err
		}
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		case <-time.After(time.Duration(wait)*time.Second + 100*time.Millisecond):
		}
	}
}

func (r *runner) once(ctx context.Context, method, path, ctype string, body []byte, hdr map[string]string) (*http.Response, []byte, error) {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, r.base+path, rd)
	if err != nil {
		return nil, nil, err
	}
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := r.http.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, client.MaxResponseBytes))
	if len(resp.Header.Values("Set-Cookie")) > 0 {
		return resp, b, errors.New("response sets a cookie")
	}
	return resp, b, err
}

// expectError sends a request and expects a signed error with a code.
func (r *runner) expectError(ctx context.Context, method, path, ctype string, body []byte, status int, code string) error {
	resp, b, err := r.raw(ctx, method, path, ctype, body, nil)
	if err != nil {
		return err
	}
	if resp.StatusCode != status {
		return fmt.Errorf("status %d, want %d", resp.StatusCode, status)
	}
	if err := r.val.ValidateEnvelope("error", b); err != nil {
		return fmt.Errorf("error body: %v", err)
	}
	var pe *client.ProtocolError
	if !errors.As(r.cl.VerifyError(resp.StatusCode, b, r.fx.Namespace), &pe) || !pe.Verified {
		return errors.New("error is not signed by the delegated online key")
	}
	if pe.Code != code {
		return fmt.Errorf("error code %q, want %q", pe.Code, code)
	}
	return nil
}

func (r *runner) request(q protocol.SearchRequest) []byte {
	q.Schema = protocol.SchemaRequest
	q.Nonce = client.NewNonce()
	b, _ := json.Marshal(q)
	return b
}

// Run checks the server at base with the trusted keyrings and fixture.
// It returns every check, passed or not.
func Run(ctx context.Context, base string, trust *signing.Trust, fx Fixture) ([]Result, error) {
	val, err := NewValidator()
	if err != nil {
		return nil, err
	}
	cl, err := client.New(base, trust)
	if err != nil {
		return nil, err
	}
	cl.RateRetries, cl.RateMaxWait = 5, time.Minute
	r := &runner{base: strings.TrimRight(base, "/"), http: &http.Client{}, cl: cl, trust: trust, val: val, fx: fx}
	ns := fx.Namespace
	prefix := "/kb/v" + protocol.Version + "/" + ns

	r.check("discovery.signed", Must, func() error {
		resp, b, err := r.raw(ctx, http.MethodGet, client.WellKnown, "", nil, nil)
		if err != nil {
			return err
		}
		if !strings.HasPrefix(resp.Header.Get("Content-Type"), protocol.MediaType) {
			return fmt.Errorf("content type %q", resp.Header.Get("Content-Type"))
		}
		if err := val.ValidateEnvelope("discovery", b); err != nil {
			return err
		}
		r.disc, err = cl.Discover(ctx)
		return err
	})
	if r.disc == nil {
		return r.results, nil
	}
	r.check("discovery.version", Must, func() error {
		if !slices.Contains(r.disc.Versions, protocol.Version) {
			return fmt.Errorf("versions %v", r.disc.Versions)
		}
		return nil
	})
	r.check("discovery.privacy", Must, func() error {
		for _, p := range protocol.RequiredPromises {
			if !slices.Contains(r.disc.Privacy.Service, p) {
				return fmt.Errorf("service promise %q missing", p)
			}
		}
		return r.disc.Privacy.Validate()
	})
	r.check("discovery.hosting_declared", Should, func() error {
		if !r.disc.Privacy.Hosting.Declared {
			return errors.New("the operator does not declare what the hosting layer logs")
		}
		return nil
	})
	r.check("search.match", Must, func() error {
		res, err := cl.Search(ctx, fx.Match)
		if err != nil {
			return err
		}
		if len(res.Hits) == 0 || res.Hits[0].Entry.ID != fx.ExpectEntry {
			return fmt.Errorf("first result is not %s", fx.ExpectEntry)
		}
		if !slices.ContainsFunc(res.Packs, func(p protocol.PackRef) bool { return p.ID == fx.ExpectPack }) {
			return fmt.Errorf("pack %s not suggested", fx.ExpectPack)
		}
		return nil
	})
	r.check("search.schema", Must, func() error {
		body := r.request(fx.Match)
		if err := val.Validate("search-request", body); err != nil {
			return fmt.Errorf("fixture request: %v", err)
		}
		resp, b, err := r.raw(ctx, http.MethodPost, prefix+"/search", protocol.MediaType, body, nil)
		if err != nil {
			return err
		}
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("status %d", resp.StatusCode)
		}
		if cc := resp.Header.Get("Cache-Control"); !strings.Contains(cc, "no-store") {
			return fmt.Errorf("search response Cache-Control %q, want no-store", cc)
		}
		return val.ValidateEnvelope("search-response", b)
	})
	r.check("search.excludes", Must, func() error {
		res, err := cl.Search(ctx, fx.NoMatch)
		if err != nil {
			return err
		}
		for _, h := range res.Hits {
			if h.Entry.ID == fx.ExpectEntry {
				return fmt.Errorf("%s returned for hardware its conditions exclude", fx.ExpectEntry)
			}
		}
		return nil
	})
	r.check("search.free_text_with_consent", Must, func() error {
		q := fx.Match
		q.FreeText = &protocol.FreeText{Text: "driver for my graphics card", Consent: "question"}
		_, err := cl.Search(ctx, q)
		return err
	})
	r.check("search.free_text_without_consent", Must, func() error {
		body := bytes.Replace(r.request(fx.Match), []byte(`"nonce"`), []byte(`"free_text":{"text":"hello","consent":"yes"},"nonce"`), 1)
		return r.expectError(ctx, http.MethodPost, prefix+"/search", protocol.MediaType, body, http.StatusBadRequest, protocol.ErrFreeTextConsent)
	})
	r.check("search.unknown_field", Must, func() error {
		body := bytes.Replace(r.request(fx.Match), []byte(`"nonce"`), []byte(`"machine_id":"x","nonce"`), 1)
		return r.expectError(ctx, http.MethodPost, prefix+"/search", protocol.MediaType, body, http.StatusBadRequest, protocol.ErrInvalidRequest)
	})
	r.check("search.sentence_as_error_code", Must, func() error {
		q := fx.Match
		q.Errors = []string{"my name is Maria and my disk is full"}
		q.Schema, q.Nonce = protocol.SchemaRequest, client.NewNonce()
		body, _ := json.Marshal(q)
		return r.expectError(ctx, http.MethodPost, prefix+"/search", protocol.MediaType, body, http.StatusBadRequest, protocol.ErrInvalidRequest)
	})
	r.check("search.too_large", Must, func() error {
		body := append([]byte(`{"pad":"`), bytes.Repeat([]byte("a"), protocol.MaxRequestBytes+16)...)
		body = append(body, '"', '}')
		return r.expectError(ctx, http.MethodPost, prefix+"/search", protocol.MediaType, body, http.StatusRequestEntityTooLarge, protocol.ErrTooLarge)
	})
	r.check("search.method", Must, func() error {
		return r.expectError(ctx, http.MethodGet, prefix+"/search", "", nil, http.StatusMethodNotAllowed, protocol.ErrMethod)
	})
	r.check("search.media_type", Must, func() error {
		return r.expectError(ctx, http.MethodPost, prefix+"/search", "text/plain", r.request(fx.Match), http.StatusUnsupportedMediaType, protocol.ErrMediaType)
	})
	r.check("version.unsupported", Must, func() error {
		resp, b, err := r.raw(ctx, http.MethodGet, "/kb/v999/"+ns+"/catalog.json", "", nil, nil)
		if err != nil {
			return err
		}
		if resp.StatusCode != http.StatusNotFound {
			return fmt.Errorf("status %d", resp.StatusCode)
		}
		env, err := signing.ParseEnvelope(b)
		if err != nil {
			return err
		}
		payload, err := base64.StdEncoding.DecodeString(env.Payload)
		if err != nil {
			return err
		}
		var e protocol.Error
		if err := json.Unmarshal(payload, &e); err != nil {
			return err
		}
		if e.Code != protocol.ErrUnsupportedVersion || !slices.Contains(e.Supported, protocol.Version) {
			return fmt.Errorf("code %q, supported %v", e.Code, e.Supported)
		}
		return r.expectError(ctx, http.MethodGet, "/kb/v999/"+ns+"/catalog.json", "", nil, http.StatusNotFound, protocol.ErrUnsupportedVersion)
	})
	r.check("namespace.unknown", Must, func() error {
		return r.expectError(ctx, http.MethodGet, "/kb/v0/no-such-namespace/catalog.json", "", nil, http.StatusNotFound, protocol.ErrUnknownNamespace)
	})
	r.check("entry.fetch", Must, func() error {
		resp, b, err := r.raw(ctx, http.MethodGet, prefix+"/"+protocol.EntryPath(fx.ExpectEntry), "", nil, nil)
		if err != nil {
			return err
		}
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("status %d", resp.StatusCode)
		}
		if err := val.ValidateEnvelope("entry", b); err != nil {
			return err
		}
		_, err = cl.Entry(ctx, ns, fx.ExpectEntry)
		return err
	})
	r.check("entry.not_found", Must, func() error {
		return r.expectError(ctx, http.MethodGet, prefix+"/entries/no-such-entry.json", "", nil, http.StatusNotFound, protocol.ErrNotFound)
	})
	r.check("catalog.packs", Must, func() error {
		_, b, err := r.raw(ctx, http.MethodGet, prefix+"/catalog.json", "", nil, nil)
		if err != nil {
			return err
		}
		if err := val.ValidateEnvelope("catalog", b); err != nil {
			return err
		}
		cat, err := cl.Catalog(ctx, ns)
		if err != nil {
			return err
		}
		found := false
		for _, cp := range cat.Packs {
			_, packRaw, err := r.raw(ctx, http.MethodGet, prefix+"/"+cp.Path, "", nil, nil)
			if err != nil {
				return err
			}
			if err := val.ValidateEnvelope("pack", packRaw); err != nil {
				return fmt.Errorf("pack %s: %v", cp.ID, err)
			}
			if _, _, _, err := cl.Pack(ctx, ns, cp); err != nil {
				return err
			}
			found = found || cp.ID == fx.ExpectPack
		}
		if !found {
			return fmt.Errorf("pack %s not in the catalog", fx.ExpectPack)
		}
		return nil
	})
	r.check("keyring.current", Must, func() error {
		_, b, err := r.raw(ctx, http.MethodGet, prefix+"/keyring.json", "", nil, nil)
		if err != nil {
			return err
		}
		if err := val.ValidateEnvelope("keyring", b); err != nil {
			return err
		}
		_, err = cl.UpdateKeyring(ctx, ns)
		return err
	})
	r.check("ratelimit.headers", Must, func() error {
		resp, _, err := r.raw(ctx, http.MethodGet, prefix+"/catalog.json", "", nil, nil)
		if err != nil {
			return err
		}
		for _, h := range []string{"RateLimit-Limit", "RateLimit-Remaining", "RateLimit-Reset"} {
			if resp.Header.Get(h) == "" {
				return fmt.Errorf("header %s missing", h)
			}
		}
		return nil
	})
	r.check("static.etag", Should, func() error {
		resp, _, err := r.raw(ctx, http.MethodGet, prefix+"/catalog.json", "", nil, nil)
		if err != nil {
			return err
		}
		etag := resp.Header.Get("ETag")
		if etag == "" {
			return errors.New("no ETag")
		}
		resp2, _, err := r.raw(ctx, http.MethodGet, prefix+"/catalog.json", "", nil, map[string]string{"If-None-Match": etag})
		if err != nil {
			return err
		}
		if resp2.StatusCode != http.StatusNotModified {
			return fmt.Errorf("If-None-Match gave %d, want 304", resp2.StatusCode)
		}
		return nil
	})
	return r.results, nil
}

// Failed returns the failed MUST checks.
func Failed(results []Result) []Result {
	var out []Result
	for _, r := range results {
		if !r.Pass && r.Level == Must {
			out = append(out, r)
		}
	}
	return out
}
