// Command kbd serves the knowledge protocol over HTTP. It is read-only:
// at start it loads (or fetches) signed build output, verifies every
// signature against pinned keyrings, checks its online key's delegations,
// and only then listens. Configuration comes from the environment so it
// runs unchanged in a container:
//
//	KBD_ADDR              listen address (default :8080)
//	KBD_DATA              directory holding one build directory per namespace
//	KBD_NAMESPACES        namespaces to serve, comma separated (default: every directory in KBD_DATA)
//	KBD_FETCH_URL         optional: fetch the namespaces from this mirror into KBD_DATA at start
//	KBD_TRUST             trust file with the pinned keyrings, or
//	KBD_TRUST_JSON        the trust file's content
//	KBD_ONLINE_KEY        online private key file (mode 0600 or stricter), or
//	KBD_ONLINE_KEY_JSON   the same key file's content (from a secret)
//	KBD_DELEGATIONS       directory with <namespace>.json delegations for the online key, or
//	KBD_DELEGATIONS_JSON  a JSON object mapping each namespace to its delegation envelope
//	KBD_RATE              requests per minute per client (default 60)
//	KBD_BURST             burst per client (default 20)
//	KBD_CLIENT_IP_HEADER  header set by a trusted proxy with the client address (rate limiting only)
//	KBD_LOG_LEVEL         debug, info (default), warn or error
//
// The operator's statement about the hosting layer in front of kbd
// (published in discovery as privacy.hosting; unset means "not declared",
// never "no logs"):
//
//	KBD_HOSTING_ACCESS_LOGS        true or false: does the ingress or proxy keep access logs
//	KBD_HOSTING_RETENTION_DAYS     days the access logs are kept (required when true)
//	KBD_HOSTING_LOG_FIELDS         comma separated: ip, time, method, path, status, size, duration, host, user_agent, referer (required when true)
//	KBD_HOSTING_QUERY_BODY_LOGGED  true or false: does it keep request bodies (required when declaring)
//	KBD_HOSTING_PROVIDER           optional name of the hosting provider
//
// kbd health-check probes /healthz and exits 0 when it answers (for
// container health checks in images without a shell).
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/openbasalt/knowledge/internal/build"
	"github.com/openbasalt/knowledge/internal/server"
	"github.com/openbasalt/knowledge/protocol"
	"github.com/openbasalt/knowledge/signing"
)

var version = "dev"

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func envInt(k string, def int) (int, error) {
	v := os.Getenv(k)
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("%s must be a positive integer", k)
	}
	return n, nil
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "health-check" {
		os.Exit(healthCheck())
	}
	if len(os.Args) > 1 && os.Args[1] == "version" {
		fmt.Println(version)
		return
	}
	var level slog.Level
	if err := level.UnmarshalText([]byte(env("KBD_LOG_LEVEL", "info"))); err != nil {
		level = slog.LevelInfo
	}
	log := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	if err := run(log); err != nil {
		log.Error("kbd stopped", "error", err.Error())
		os.Exit(1)
	}
}

func healthCheck() int {
	addr := env("KBD_ADDR", ":8080")
	if strings.HasPrefix(addr, ":") {
		addr = "127.0.0.1" + addr
	}
	c := &http.Client{Timeout: 3 * time.Second}
	resp, err := c.Get("http://" + addr + "/healthz")
	if err != nil {
		return 1
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}

// hostingFromEnv reads the hosting statement through get (os.Getenv). It
// only declares what the operator set, and refuses an incomplete
// statement rather than publishing a partial one.
func hostingFromEnv(get func(string) string) (protocol.Hosting, error) {
	var h protocol.Hosting
	flag := func(k string) (*bool, error) {
		switch v := strings.TrimSpace(get(k)); v {
		case "":
			return nil, nil
		case "true", "false":
			b := v == "true"
			return &b, nil
		default:
			return nil, fmt.Errorf("%s must be true or false", k)
		}
	}
	logs, err := flag("KBD_HOSTING_ACCESS_LOGS")
	if err != nil {
		return h, err
	}
	body, err := flag("KBD_HOSTING_QUERY_BODY_LOGGED")
	if err != nil {
		return h, err
	}
	days, fields, provider := get("KBD_HOSTING_RETENTION_DAYS"), get("KBD_HOSTING_LOG_FIELDS"), get("KBD_HOSTING_PROVIDER")
	if logs == nil {
		if body != nil || days != "" || fields != "" || provider != "" {
			return h, errors.New("KBD_HOSTING_* set without KBD_HOSTING_ACCESS_LOGS")
		}
		return h, nil
	}
	h.Declared, h.AccessLogs, h.QueryBodyLogged, h.Provider = true, logs, body, strings.TrimSpace(provider)
	if body == nil {
		return h, errors.New("KBD_HOSTING_QUERY_BODY_LOGGED is required when KBD_HOSTING_ACCESS_LOGS is set")
	}
	if days != "" {
		n, err := strconv.Atoi(strings.TrimSpace(days))
		if err != nil {
			return h, errors.New("KBD_HOSTING_RETENTION_DAYS must be a whole number of days")
		}
		h.RetentionDays = &n
	}
	if fields != "" {
		for _, f := range strings.Split(fields, ",") {
			h.Fields = append(h.Fields, strings.TrimSpace(f))
		}
	}
	if err := h.Validate(); err != nil {
		return h, fmt.Errorf("KBD_HOSTING_*: %v", err)
	}
	return h, nil
}

func onlineKey() (*signing.Signer, error) {
	if v := os.Getenv("KBD_ONLINE_KEY_JSON"); v != "" {
		return signing.ParsePrivate([]byte(v))
	}
	path := os.Getenv("KBD_ONLINE_KEY")
	if path == "" {
		return nil, errors.New("set KBD_ONLINE_KEY or KBD_ONLINE_KEY_JSON")
	}
	return signing.LoadPrivate(path)
}

func run(log *slog.Logger) error {
	data := env("KBD_DATA", "/data")
	trustFile := env("KBD_TRUST", "/etc/kbd/trust.json")
	delegDir := env("KBD_DELEGATIONS", "/etc/kbd/delegations")
	var err error
	rate, err := envInt("KBD_RATE", 60)
	if err != nil {
		return err
	}
	burst, err := envInt("KBD_BURST", 20)
	if err != nil {
		return err
	}
	var trust *signing.Trust
	if v := os.Getenv("KBD_TRUST_JSON"); v != "" {
		trust, err = signing.ParseTrust([]byte(v))
	} else {
		trust, err = signing.LoadTrust(trustFile)
	}
	if err != nil {
		return fmt.Errorf("trust: %v", err)
	}
	inline := map[string]*signing.Envelope{}
	if v := os.Getenv("KBD_DELEGATIONS_JSON"); v != "" {
		if err := json.Unmarshal([]byte(v), &inline); err != nil {
			return fmt.Errorf("KBD_DELEGATIONS_JSON: %v", err)
		}
	}
	hosting, err := hostingFromEnv(os.Getenv)
	if err != nil {
		return err
	}
	if !hosting.Declared {
		log.Warn("hosting statement not declared: discovery tells clients the host may keep client addresses (set KBD_HOSTING_*)")
	}
	key, err := onlineKey()
	if err != nil {
		return fmt.Errorf("online key: %v", err)
	}
	var names []string
	if v := os.Getenv("KBD_NAMESPACES"); v != "" {
		for _, n := range strings.Split(v, ",") {
			names = append(names, strings.TrimSpace(n))
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if url := os.Getenv("KBD_FETCH_URL"); url != "" {
		if len(names) == 0 {
			return errors.New("KBD_FETCH_URL needs KBD_NAMESPACES")
		}
		for _, n := range names {
			fctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
			err := server.Fetch(fctx, url, n, data)
			cancel()
			if err != nil {
				return fmt.Errorf("fetch %s: %v", n, err)
			}
			log.Info("fetched", "namespace", n)
		}
	}
	if len(names) == 0 {
		des, err := os.ReadDir(data)
		if err != nil {
			return err
		}
		for _, de := range des {
			if de.IsDir() && signing.ValidNamespace(de.Name()) {
				names = append(names, de.Name())
			}
		}
	}
	cfg := server.Config{Online: key, Trust: trust, Delegations: map[string]*signing.Envelope{},
		Requests: rate, Period: time.Minute, Burst: burst,
		ClientIPHeader: os.Getenv("KBD_CLIENT_IP_HEADER"), Logger: log, Hosting: hosting}
	for _, n := range names {
		dir := filepath.Join(data, n)
		if err := build.FollowKeyrings(dir, trust); err != nil {
			return fmt.Errorf("%s: %v", n, err)
		}
		ns, err := build.LoadNamespace(dir, trust)
		if err != nil {
			return fmt.Errorf("%s: %v", n, err)
		}
		d := inline[n]
		if d == nil {
			b, err := os.ReadFile(filepath.Join(delegDir, n+".json"))
			if err != nil {
				return fmt.Errorf("%s delegation: %v", n, err)
			}
			if d, err = signing.ParseEnvelope(b); err != nil {
				return fmt.Errorf("%s delegation: %v", n, err)
			}
		}
		cfg.Namespaces = append(cfg.Namespaces, ns)
		cfg.Delegations[n] = d
		log.Info("loaded", "namespace", n, "version", ns.Catalog.Version, "entries", len(ns.Entries), "packs", len(ns.Packs))
	}
	srv, err := server.New(cfg)
	if err != nil {
		return err
	}
	hs := &http.Server{Addr: env("KBD_ADDR", ":8080"), Handler: srv,
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 20 * time.Second,
		IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				srv.Sweep()
			}
		}
	}()
	errc := make(chan error, 1)
	go func() { errc <- hs.ListenAndServe() }()
	log.Info("listening", "addr", hs.Addr, "version", version)
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return hs.Shutdown(sctx)
}
