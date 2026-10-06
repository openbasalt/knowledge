// Package server is the HTTP side of the knowledge protocol (kbd): a
// read-only service that answers from namespaces verified at start, signs
// every dynamic response with its delegated online key, serves the
// publisher-signed files as they are, limits clients without storing
// their addresses, and logs nothing about what was asked.
package server

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/openbasalt/knowledge/internal/build"
	"github.com/openbasalt/knowledge/internal/index"
	"github.com/openbasalt/knowledge/internal/ratelimit"
	"github.com/openbasalt/knowledge/protocol"
	"github.com/openbasalt/knowledge/signing"
)

// WellKnown is the discovery path.
const WellKnown = "/.well-known/openbasalt-knowledge"

// Prefix is the path prefix of protocol version 0.
const Prefix = "/kb/v" + protocol.Version + "/"

// Config of a server.
type Config struct {
	Namespaces     []*build.Namespace
	Online         *signing.Signer              // the delegated online key
	Delegations    map[string]*signing.Envelope // per namespace, signed by its publisher
	Trust          *signing.Trust               // to check the delegations at start
	Requests       int                          // rate limit: requests per Period per client
	Period         time.Duration
	Burst          int
	ClientIPHeader string // trusted proxy header with the client address (e.g. X-Forwarded-For); empty: the TCP peer
	Logger         *slog.Logger
	Now            func() time.Time

	// Hosting is the operator's statement about the hosting layer in front
	// of kbd (ingress access logs and their retention), published in
	// discovery next to the service's own promises. The zero value is
	// "not declared": clients then assume the host may keep addresses.
	Hosting protocol.Hosting
}

type nsState struct {
	data       *build.Namespace
	ix         *index.Index
	delegation *signing.Envelope
	bundle     protocol.BundleRef
}

// Server implements http.Handler.
type Server struct {
	cfg     Config
	ns      map[string]*nsState
	names   []string
	limiter *ratelimit.Limiter
	mux     *http.ServeMux
	log     *slog.Logger
	now     func() time.Time

	mu       sync.Mutex
	counters map[string]int64
}

// New checks the configuration (every delegation must be valid now, for
// the online key, signed by a publisher of its namespace) and builds the
// indexes.
func New(cfg Config) (*Server, error) {
	if cfg.Online == nil {
		return nil, errors.New("server needs an online key")
	}
	if cfg.Requests <= 0 {
		cfg.Requests, cfg.Period, cfg.Burst = 60, time.Minute, 20
	}
	if err := cfg.Hosting.Validate(); err != nil {
		return nil, fmt.Errorf("hosting statement: %v", err)
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	s := &Server{cfg: cfg, ns: map[string]*nsState{}, log: cfg.Logger, now: cfg.Now,
		limiter: ratelimit.New(cfg.Requests, cfg.Period, cfg.Burst), counters: map[string]int64{}}
	if s.now == nil {
		s.now = time.Now
	}
	for _, n := range cfg.Namespaces {
		env := cfg.Delegations[n.Name]
		if env == nil {
			return nil, fmt.Errorf("namespace %s: no delegation for the online key", n.Name)
		}
		d, err := cfg.Trust.OpenDelegation(env, n.Name)
		if err != nil {
			return nil, fmt.Errorf("namespace %s: %v", n.Name, err)
		}
		if d.Key.KeyID != cfg.Online.KeyID() {
			return nil, fmt.Errorf("namespace %s: the delegation is for key %s, not %s", n.Name, d.Key.KeyID, cfg.Online.KeyID())
		}
		var entries []*protocol.Entry
		for _, e := range n.Entries {
			entries = append(entries, e.Entry)
		}
		s.ns[n.Name] = &nsState{data: n, ix: index.New(entries), delegation: env,
			bundle: protocol.BundleRef{Version: n.Catalog.Version, Digest: n.CatalogDigest}}
		s.names = append(s.names, n.Name)
	}
	if len(s.ns) == 0 {
		return nil, errors.New("no namespace to serve")
	}
	slices.Sort(s.names)
	s.routes()
	return s, nil
}

// SetClock replaces the clock of the server and its limiter (tests).
func (s *Server) SetClock(now func() time.Time) {
	s.now = now
	s.limiter.SetClock(now)
}

func (s *Server) routes() {
	m := http.NewServeMux()
	m.HandleFunc("GET /healthz", s.health)
	m.HandleFunc("GET /statusz", s.status)
	m.HandleFunc("GET "+WellKnown, s.limited("discovery", s.discovery))
	m.HandleFunc("GET "+Prefix+"{ns}/catalog.json", s.limited("catalog", s.static(func(n *nsState, _ string) []byte { return n.data.CatalogRaw })))
	m.HandleFunc("GET "+Prefix+"{ns}/keyring.json", s.limited("keyring", s.static(func(n *nsState, _ string) []byte { return n.data.KeyringRaw })))
	m.HandleFunc("GET "+Prefix+"{ns}/keyring/{file}", s.limited("keyring", s.static(s.keyringFile)))
	m.HandleFunc("GET "+Prefix+"{ns}/packs/{file}", s.limited("pack", s.static(s.packFile)))
	m.HandleFunc("GET "+Prefix+"{ns}/entries/{file}", s.limited("entry", s.static(s.entryFile)))
	m.HandleFunc("POST "+Prefix+"{ns}/search", s.limited("search", s.search))
	m.HandleFunc(Prefix+"{ns}/search", s.limited("search", s.methodNotAllowed))
	m.HandleFunc("/kb/{version}/", s.limited("other", s.unsupported))
	m.HandleFunc("/", s.limited("other", func(w http.ResponseWriter, r *http.Request) {
		s.fail(w, http.StatusNotFound, protocol.ErrNotFound, "no such resource", 0)
	}))
	s.mux = m
}

// statusRecorder keeps the status and size for the access log.
type statusRecorder struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (w *statusRecorder) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusRecorder) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytes += n
	return n, err
}

// ServeHTTP adds the common headers and the access log line. The log line
// holds the route name, never the path, the query, a header or the body.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	h := w.Header()
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Content-Security-Policy", "default-src 'none'")
	rec := &statusRecorder{ResponseWriter: w}
	s.mux.ServeHTTP(rec, r)
	route := r.Pattern
	if route == "" {
		route = "none"
	}
	s.count("http " + strconv.Itoa(rec.status))
	s.log.Info("request", "route", route, "status", rec.status, "bytes", rec.bytes,
		"ms", time.Since(start).Milliseconds())
}

func (s *Server) count(key string) {
	s.mu.Lock()
	s.counters[key]++
	s.mu.Unlock()
}

func (s *Server) clientKey(r *http.Request) string {
	if hdr := s.cfg.ClientIPHeader; hdr != "" {
		if v := r.Header.Get(hdr); v != "" {
			first, _, _ := strings.Cut(v, ",")
			return strings.TrimSpace(first)
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// limited applies the rate limit and its headers.
func (s *Server) limited(name string, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		d := s.limiter.Allow(s.clientKey(r))
		hd := w.Header()
		hd.Set("RateLimit-Policy", fmt.Sprintf("%d;w=%d", s.cfg.Burst, int(s.cfg.Period.Seconds())))
		hd.Set("RateLimit-Limit", strconv.Itoa(s.cfg.Burst))
		hd.Set("RateLimit-Remaining", strconv.Itoa(d.Remaining))
		hd.Set("RateLimit-Reset", strconv.Itoa(int(d.Reset.Seconds()+0.999)))
		if !d.OK {
			retry := int(d.RetryAfter.Seconds() + 0.999)
			hd.Set("Retry-After", strconv.Itoa(retry))
			s.count("rate_limited")
			s.fail(w, http.StatusTooManyRequests, protocol.ErrRateLimited, "too many requests", retry)
			return
		}
		s.count("route " + name)
		h(w, r)
	}
}

func (s *Server) writeEnvelope(w http.ResponseWriter, status int, env *signing.Envelope) {
	b, err := jsonMarshal(env)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", protocol.MediaType)
	w.WriteHeader(status)
	_, _ = w.Write(b)
}

// fail writes an error, signed by the online key.
func (s *Server) fail(w http.ResponseWriter, status int, code, msg string, retry int) {
	e := protocol.Error{Schema: protocol.SchemaError, Code: code, Message: msg, RetryAfter: retry}
	if code == protocol.ErrUnsupportedVersion {
		e.Supported = protocol.Supported
	}
	env, err := signing.SealJSON(protocol.TypeError, e, s.cfg.Online)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	s.count("error " + code)
	s.writeEnvelope(w, status, env)
}

func (s *Server) namespace(w http.ResponseWriter, r *http.Request) *nsState {
	n := s.ns[r.PathValue("ns")]
	if n == nil {
		s.fail(w, http.StatusNotFound, protocol.ErrUnknownNamespace, "namespace not served here", 0)
	}
	return n
}

var reKeyringFile = regexp.MustCompile(`^([1-9][0-9]{0,5})\.json$`)

func (s *Server) keyringFile(n *nsState, file string) []byte {
	m := reKeyringFile.FindStringSubmatch(file)
	if m == nil {
		return nil
	}
	v, _ := strconv.Atoi(m[1])
	return n.data.Keyrings[v]
}

func (s *Server) packFile(n *nsState, file string) []byte {
	for _, p := range n.data.Packs {
		if "packs/"+file == p.Meta.Path {
			return p.Raw
		}
	}
	return nil
}

func (s *Server) entryFile(n *nsState, file string) []byte {
	id, ok := strings.CutSuffix(file, ".json")
	if !ok || !protocol.ValidID(id) {
		return nil
	}
	if e := n.data.Entries[id]; e != nil {
		return e.Raw
	}
	return nil
}

// static serves a publisher-signed file exactly as built, with its digest
// as the ETag.
func (s *Server) static(get func(*nsState, string) []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		n := s.namespace(w, r)
		if n == nil {
			return
		}
		b := get(n, r.PathValue("file"))
		if b == nil {
			s.fail(w, http.StatusNotFound, protocol.ErrNotFound, "no such object", 0)
			return
		}
		etag := `"` + signing.DigestBytes(b) + `"`
		h := w.Header()
		h.Set("ETag", etag)
		h.Set("Cache-Control", "public, max-age=300")
		h.Set("Content-Type", protocol.MediaType)
		if r.Header.Get("If-None-Match") == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		h.Set("Content-Length", strconv.Itoa(len(b)))
		_, _ = w.Write(b)
	}
}

func (s *Server) discovery(w http.ResponseWriter, r *http.Request) {
	d := protocol.Discovery{
		Schema: protocol.SchemaDiscovery, Versions: protocol.Supported, IssuedAt: s.now().UTC().Truncate(time.Second),
		Limits: protocol.Limits{MaxRequestBytes: protocol.MaxRequestBytes, MaxResults: protocol.MaxResults,
			RateLimit: protocol.RateLimit{Requests: s.cfg.Requests, Seconds: int(s.cfg.Period.Seconds()), Burst: s.cfg.Burst}},
		Privacy: protocol.Privacy{Service: protocol.ServicePromises, Hosting: s.cfg.Hosting},
	}
	for _, name := range s.names {
		n := s.ns[name]
		ring, _ := s.cfg.Trust.Keyring(name)
		d.Namespaces = append(d.Namespaces, protocol.NamespaceInfo{Name: name, Languages: n.data.Languages,
			Bundle: n.bundle, Keyring: ring.Version, Delegation: n.delegation})
	}
	env, err := signing.SealJSON(protocol.TypeDiscovery, d, s.cfg.Online)
	if err != nil {
		s.fail(w, http.StatusInternalServerError, protocol.ErrInternal, "signing failed", 0)
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=60")
	s.writeEnvelope(w, http.StatusOK, env)
}

func (s *Server) methodNotAllowed(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Allow", "POST")
	s.fail(w, http.StatusMethodNotAllowed, protocol.ErrMethod, "search is POST only", 0)
}

func (s *Server) unsupported(w http.ResponseWriter, r *http.Request) {
	if "v"+protocol.Version == r.PathValue("version") {
		s.fail(w, http.StatusNotFound, protocol.ErrNotFound, "no such resource", 0)
		return
	}
	s.fail(w, http.StatusNotFound, protocol.ErrUnsupportedVersion, "protocol version not supported", 0)
}

func (s *Server) search(w http.ResponseWriter, r *http.Request) {
	n := s.namespace(w, r)
	if n == nil {
		return
	}
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mt != protocol.MediaType {
		s.fail(w, http.StatusUnsupportedMediaType, protocol.ErrMediaType, "send application/json", 0)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, protocol.MaxRequestBytes))
	if err != nil {
		s.fail(w, http.StatusRequestEntityTooLarge, protocol.ErrTooLarge, "request body too large", 0)
		return
	}
	req, err := protocol.ParseRequest(body)
	if err != nil {
		var re *protocol.RequestError
		code := protocol.ErrInvalidRequest
		msg := "request is not valid"
		if errors.As(err, &re) {
			code, msg = re.Code, re.Msg
		}
		status := http.StatusBadRequest
		if code == protocol.ErrTooLarge {
			status = http.StatusRequestEntityTooLarge
		}
		s.fail(w, status, code, msg, 0)
		return
	}
	if req.Namespace != r.PathValue("ns") {
		s.fail(w, http.StatusBadRequest, protocol.ErrInvalidRequest, "namespace differs from the path", 0)
		return
	}
	if req.FreeText != nil {
		s.count("search free_text")
	}
	hits := n.ix.Search(req)
	resp := protocol.SearchResponse{
		Schema: protocol.SchemaResponse, Namespace: req.Namespace, RequestDigest: signing.DigestBytes(body),
		Nonce: req.Nonce, IssuedAt: s.now().UTC().Truncate(time.Second), Bundle: n.bundle, Results: []protocol.Result{},
	}
	packs := map[string]bool{}
	for _, h := range hits {
		le := n.data.Entries[h.Entry.ID]
		resp.Results = append(resp.Results, protocol.Result{ID: h.Entry.ID, Score: h.Score, Digest: le.Digest,
			Pack: h.Entry.Pack, Matched: h.Matched, Entry: le.Env})
		if h.Entry.Pack != protocol.CorePack {
			packs[h.Entry.Pack] = true
		}
	}
	facts := protocol.FactsOf(req)
	for _, cp := range n.data.Catalog.Packs {
		if cp.ID == protocol.CorePack {
			continue
		}
		m := cp.AppliesTo.Match(facts)
		if packs[cp.ID] || !m.Excluded && slices.ContainsFunc(m.Matched, func(g string) bool { return g == "hardware" || g == "packages" }) {
			resp.Packs = append(resp.Packs, protocol.PackRef{ID: cp.ID, Version: cp.Version, Digest: cp.Digest})
		}
	}
	if len(hits) == 0 {
		s.count("search empty")
	}
	s.count("search " + req.Namespace)
	env, err := signing.SealJSON(protocol.TypeSearch, resp, s.cfg.Online)
	if err != nil {
		s.fail(w, http.StatusInternalServerError, protocol.ErrInternal, "signing failed", 0)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	s.writeEnvelope(w, http.StatusOK, env)
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", protocol.MediaType)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(`{"status":"ok"}` + "\n"))
}

// status publishes the aggregate counters: counts per route, status,
// error code and namespace. Nothing about a single request.
func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	snapshot := make(map[string]int64, len(s.counters))
	for k, v := range s.counters {
		snapshot[k] = v
	}
	s.mu.Unlock()
	entries := 0
	for _, n := range s.ns {
		entries += n.ix.Len()
	}
	b, _ := jsonMarshal(map[string]any{"counters": snapshot, "namespaces": s.names, "entries": entries,
		"rate_limited_clients_in_memory": s.limiter.Clients()})
	w.Header().Set("Content-Type", protocol.MediaType)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(b)
}

// Sweep drops idle rate limit buckets; kbd calls it every minute.
func (s *Server) Sweep() { s.limiter.Sweep() }
