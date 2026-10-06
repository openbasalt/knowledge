// Package build turns a validated namespace source into the signed,
// static layout every server and mirror serves:
//
//	<out>/<ns>/keyring.json           latest keyring (envelope)
//	<out>/<ns>/keyring/<n>.json       every keyring version, for rotation
//	<out>/<ns>/catalog.json           signed catalog of packs
//	<out>/<ns>/packs/<id>-<ver>.json  signed packs (core and topic packs)
//	<out>/<ns>/entries/<id>.json      signed entries, one per file
//
// The output is reproducible: Ed25519 signatures are deterministic, and
// the time stamped into packs and the catalog comes from the options.
package build

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/openbasalt/knowledge/internal/source"
	"github.com/openbasalt/knowledge/protocol"
	"github.com/openbasalt/knowledge/signing"
)

// Options of a build.
type Options struct {
	Out      string              // output root; the namespace goes in <Out>/<ns>
	Version  string              // bundle version stamped on packs and the catalog
	Created  time.Time           // build time (use SOURCE_DATE_EPOCH for reproducible builds)
	Signer   *signing.Signer     // a publisher key of the namespace's keyring
	Keyrings []*signing.Envelope // every keyring version, oldest first
}

// Result summarizes a build.
type Result struct {
	Dir     string
	Entries int
	Packs   []protocol.CatalogPack
}

func marshal(v any) ([]byte, error) {
	b, err := json.MarshalIndent(v, "", " ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

func write(path string, b []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

// Build signs and writes the namespace. It refuses a signer that is not a
// publisher key of the newest keyring, and checks its own output with the
// same verification clients use.
func Build(src *source.Source, o Options) (*Result, error) {
	ns := src.Namespace.Namespace
	if o.Signer == nil || len(o.Keyrings) == 0 {
		return nil, fmt.Errorf("build needs a signing key and the namespace keyring")
	}
	if !regexpVersion(o.Version) {
		return nil, fmt.Errorf("version %q: digits and dots, e.g. 2026.10.05", o.Version)
	}
	trust := signing.NewTrust()
	trust.Now = func() time.Time { return o.Created }
	if _, err := trust.Pin(o.Keyrings[0]); err != nil {
		return nil, fmt.Errorf("keyring: %v", err)
	}
	for _, k := range o.Keyrings[1:] {
		if _, err := trust.Update(k); err != nil {
			return nil, fmt.Errorf("keyring rotation: %v", err)
		}
	}
	ring, _ := trust.Keyring(ns)
	if ring == nil {
		return nil, fmt.Errorf("keyring is for another namespace, not %q", ns)
	}
	probe, err := signing.Seal(protocol.TypeEntry, []byte("probe"), o.Signer)
	if err != nil {
		return nil, err
	}
	if _, err := trust.OpenPublisher(probe, ns, protocol.TypeEntry); err != nil {
		return nil, fmt.Errorf("key %s is not a publisher key of %s keyring v%d", o.Signer.KeyID(), ns, ring.Version)
	}

	dir := filepath.Join(o.Out, ns)
	created := o.Created.UTC()
	byPack := map[string][]*signing.Envelope{}
	for _, e := range src.Entries {
		env, err := signing.SealJSON(protocol.TypeEntry, e, o.Signer)
		if err != nil {
			return nil, err
		}
		b, err := marshal(env)
		if err != nil {
			return nil, err
		}
		if err := write(filepath.Join(dir, protocol.EntryPath(e.ID)), b); err != nil {
			return nil, err
		}
		byPack[e.Pack] = append(byPack[e.Pack], env)
	}

	defs := map[string]source.PackDef{}
	for _, p := range src.Namespace.Packs {
		defs[p.ID] = p
	}
	core := source.PackDef{ID: protocol.CorePack, Title: map[string]string{}, Description: map[string]string{}}
	for _, l := range src.Namespace.Languages {
		core.Title[l] = src.Namespace.Title[l]
		core.Description[l] = src.Namespace.Description[l]
	}
	defs[protocol.CorePack] = core

	cat := protocol.Catalog{Schema: protocol.SchemaCatalog, Namespace: ns, Version: o.Version, Created: created}
	ids := make([]string, 0, len(byPack))
	for id := range byPack {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		def := defs[id]
		p := protocol.Pack{Schema: protocol.SchemaPack, Namespace: ns, ID: id, Version: o.Version,
			Created: created, AppliesTo: def.AppliesTo, Entries: byPack[id]}
		env, err := signing.SealJSON(protocol.TypePack, p, o.Signer)
		if err != nil {
			return nil, err
		}
		b, err := marshal(env)
		if err != nil {
			return nil, err
		}
		path := protocol.PackPath(id, o.Version)
		if err := write(filepath.Join(dir, path), b); err != nil {
			return nil, err
		}
		cat.Packs = append(cat.Packs, protocol.CatalogPack{
			ID: id, Version: o.Version, Path: path, Size: int64(len(b)), Digest: signing.DigestBytes(b),
			Entries: len(byPack[id]), AppliesTo: def.AppliesTo, Titles: def.Title, Descriptions: def.Description,
		})
	}
	catEnv, err := signing.SealJSON(protocol.TypeCatalog, cat, o.Signer)
	if err != nil {
		return nil, err
	}
	b, err := marshal(catEnv)
	if err != nil {
		return nil, err
	}
	if err := write(filepath.Join(dir, "catalog.json"), b); err != nil {
		return nil, err
	}
	for _, k := range o.Keyrings {
		peek, err := keyringVersion(k)
		if err != nil {
			return nil, err
		}
		kb, err := marshal(k)
		if err != nil {
			return nil, err
		}
		if err := write(filepath.Join(dir, protocol.KeyringPath(peek)), kb); err != nil {
			return nil, err
		}
		if peek == ring.Version {
			if err := write(filepath.Join(dir, "keyring.json"), kb); err != nil {
				return nil, err
			}
		}
	}
	// Check the output the way a server loads it.
	if _, err := LoadNamespace(dir, trust); err != nil {
		return nil, fmt.Errorf("self-check of the output failed: %v", err)
	}
	return &Result{Dir: dir, Entries: len(src.Entries), Packs: cat.Packs}, nil
}

func keyringVersion(env *signing.Envelope) (int, error) {
	var k signing.Keyring
	b, err := decodePayload(env)
	if err != nil {
		return 0, err
	}
	if err := json.Unmarshal(b, &k); err != nil {
		return 0, err
	}
	return k.Version, nil
}
