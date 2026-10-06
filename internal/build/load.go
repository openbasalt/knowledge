package build

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"

	"github.com/openbasalt/knowledge/protocol"
	"github.com/openbasalt/knowledge/signing"
)

var reVersion = regexp.MustCompile(`^[0-9][0-9.]{0,31}$`)

func regexpVersion(s string) bool { return reVersion.MatchString(s) }

func decodePayload(env *signing.Envelope) ([]byte, error) {
	return base64.StdEncoding.DecodeString(env.Payload)
}

// LoadedEntry is a verified entry with its envelope and digest.
type LoadedEntry struct {
	Entry  *protocol.Entry
	Env    *signing.Envelope
	Digest string
	Raw    []byte // the envelope file as served
}

// LoadedPack is a verified pack file.
type LoadedPack struct {
	Meta protocol.CatalogPack
	Raw  []byte // the pack file bytes (their digest is in the catalog)
}

// Namespace is a fully verified namespace directory.
type Namespace struct {
	Name          string
	Catalog       *protocol.Catalog
	CatalogRaw    []byte
	CatalogDigest string
	KeyringRaw    []byte         // latest keyring file
	Keyrings      map[int][]byte // every keyring version file
	Packs         map[string]*LoadedPack
	Entries       map[string]*LoadedEntry
	Languages     []string
}

func readEnvelope(path string) (*signing.Envelope, []byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	env, err := signing.ParseEnvelope(b)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %v", path, err)
	}
	return env, b, nil
}

// LoadNamespace reads <dir> (one namespace of a build output) and verifies
// everything against trust: the catalog signature, every pack's size,
// digest and signature, every entry's signature, and that each entry file
// matches the entry in its pack. Nothing unverified is returned.
func LoadNamespace(dir string, trust *signing.Trust) (*Namespace, error) {
	ns := filepath.Base(dir)
	catEnv, catRaw, err := readEnvelope(filepath.Join(dir, "catalog.json"))
	if err != nil {
		return nil, err
	}
	cat, catDigest, err := protocol.OpenCatalog(trust, catEnv, ns)
	if err != nil {
		return nil, err
	}
	out := &Namespace{Name: ns, Catalog: cat, CatalogRaw: catRaw, CatalogDigest: catDigest,
		Keyrings: map[int][]byte{}, Packs: map[string]*LoadedPack{}, Entries: map[string]*LoadedEntry{}}
	langs := map[string]bool{}
	for _, cp := range cat.Packs {
		raw, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(cp.Path)))
		if err != nil {
			return nil, err
		}
		if int64(len(raw)) != cp.Size || signing.DigestBytes(raw) != cp.Digest {
			return nil, fmt.Errorf("pack %s: size or digest does not match the catalog", cp.ID)
		}
		env, err := signing.ParseEnvelope(raw)
		if err != nil {
			return nil, err
		}
		p, entries, err := protocol.OpenPack(trust, env, ns)
		if err != nil {
			return nil, err
		}
		if p.ID != cp.ID || p.Version != cp.Version {
			return nil, fmt.Errorf("pack file %s holds %s %s", cp.Path, p.ID, p.Version)
		}
		out.Packs[cp.ID] = &LoadedPack{Meta: cp, Raw: raw}
		for i, e := range entries {
			if _, dup := out.Entries[e.ID]; dup {
				return nil, fmt.Errorf("entry %s is in two packs", e.ID)
			}
			eenv := p.Entries[i]
			digest, err := eenv.Digest()
			if err != nil {
				return nil, err
			}
			fileEnv, fileRaw, err := readEnvelope(filepath.Join(dir, filepath.FromSlash(protocol.EntryPath(e.ID))))
			if err != nil {
				return nil, err
			}
			if fd, err := fileEnv.Digest(); err != nil || fd != digest {
				return nil, fmt.Errorf("entry file %s differs from the entry in pack %s", e.ID, p.ID)
			}
			if _, _, err := protocol.OpenEntry(trust, fileEnv, ns); err != nil {
				return nil, err
			}
			out.Entries[e.ID] = &LoadedEntry{Entry: e, Env: eenv, Digest: digest, Raw: fileRaw}
			for l := range e.Variants {
				langs[l] = true
			}
		}
	}
	ring, ok := trust.Keyring(ns)
	if !ok {
		return nil, fmt.Errorf("namespace %s is not trusted", ns)
	}
	if out.KeyringRaw, err = os.ReadFile(filepath.Join(dir, "keyring.json")); err != nil {
		return nil, err
	}
	files, _ := filepath.Glob(filepath.Join(dir, "keyring", "*.json"))
	for _, f := range files {
		env, raw, err := readEnvelope(f)
		if err != nil {
			return nil, err
		}
		v, err := keyringVersion(env)
		if err != nil {
			return nil, err
		}
		if filepath.Base(f) != fmt.Sprintf("%d.json", v) {
			return nil, fmt.Errorf("%s holds keyring version %d", f, v)
		}
		out.Keyrings[v] = raw
	}
	if _, ok := out.Keyrings[ring.Version]; !ok {
		return nil, fmt.Errorf("keyring/%d.json (the trusted version) is missing", ring.Version)
	}
	for l := range langs {
		out.Languages = append(out.Languages, l)
	}
	sort.Strings(out.Languages)
	return out, nil
}

// FollowKeyrings applies the keyring versions found in <dir>/keyring/ to
// trust in order, so a server pinned to an older keyring follows the
// rotations the build output carries (each verified by the one before).
func FollowKeyrings(dir string, trust *signing.Trust) error {
	files, _ := filepath.Glob(filepath.Join(dir, "keyring", "*.json"))
	type kv struct {
		v   int
		env *signing.Envelope
	}
	var list []kv
	for _, f := range files {
		env, _, err := readEnvelope(f)
		if err != nil {
			return err
		}
		v, err := keyringVersion(env)
		if err != nil {
			return err
		}
		list = append(list, kv{v, env})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].v < list[j].v })
	for _, k := range list {
		if _, err := trust.Update(k.env); err != nil {
			return fmt.Errorf("keyring %d: %v", k.v, err)
		}
	}
	return nil
}
