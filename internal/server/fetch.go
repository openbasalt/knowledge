package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/openbasalt/knowledge/protocol"
	"github.com/openbasalt/knowledge/signing"
)

// Fetch copies one namespace of a published build (a static mirror or
// another server) into dir/<ns>. It checks nothing itself: the files are
// verified by build.LoadNamespace before anything is served, and a file
// that fails there is never used.
func Fetch(ctx context.Context, base, ns, dir string) error {
	if !signing.ValidNamespace(ns) {
		return fmt.Errorf("namespace %q is not valid", ns)
	}
	base = strings.TrimRight(base, "/") + "/kb/v" + protocol.Version + "/" + ns + "/"
	dest := filepath.Join(dir, ns)
	hc := &http.Client{}
	get := func(rel string) ([]byte, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+rel, nil)
		if err != nil {
			return nil, err
		}
		resp, err := hc.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("%s: status %d", rel, resp.StatusCode)
		}
		b, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
		if err != nil {
			return nil, err
		}
		path := filepath.Join(dest, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return nil, err
		}
		return b, os.WriteFile(path, b, 0o644)
	}
	payload := func(b []byte, v any) error {
		env, err := signing.ParseEnvelope(b)
		if err != nil {
			return err
		}
		raw, err := base64.StdEncoding.DecodeString(env.Payload)
		if err != nil {
			return err
		}
		return json.Unmarshal(raw, v)
	}
	kb, err := get("keyring.json")
	if err != nil {
		return err
	}
	var ring signing.Keyring
	if err := payload(kb, &ring); err != nil {
		return err
	}
	if ring.Version < 1 || ring.Version > 100000 {
		return fmt.Errorf("keyring version %d", ring.Version)
	}
	for v := 1; v <= ring.Version; v++ {
		if _, err := get(protocol.KeyringPath(v)); err != nil {
			return err
		}
	}
	cb, err := get("catalog.json")
	if err != nil {
		return err
	}
	var cat protocol.Catalog
	if err := payload(cb, &cat); err != nil {
		return err
	}
	for _, cp := range cat.Packs {
		if !protocol.ValidID(cp.ID) || cp.Path != protocol.PackPath(cp.ID, cp.Version) {
			return fmt.Errorf("catalog pack %q has an unexpected path", cp.ID)
		}
		pb, err := get(cp.Path)
		if err != nil {
			return err
		}
		var p protocol.Pack
		if err := payload(pb, &p); err != nil {
			return err
		}
		for _, e := range p.Entries {
			var entry protocol.Entry
			raw, err := base64.StdEncoding.DecodeString(e.Payload)
			if err != nil || json.Unmarshal(raw, &entry) != nil || !protocol.ValidID(entry.ID) {
				return fmt.Errorf("pack %s holds an entry that cannot be read", cp.ID)
			}
			if _, err := get(protocol.EntryPath(entry.ID)); err != nil {
				return err
			}
		}
	}
	return nil
}
