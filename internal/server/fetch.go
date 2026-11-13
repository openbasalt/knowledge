package server

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/openbasalt/knowledge/internal/build"
	"github.com/openbasalt/knowledge/protocol"
	"github.com/openbasalt/knowledge/signing"
)

// stagingPrefix names the temporary directories Fetch creates inside the
// data directory. kbd never loads them: namespace names cannot start with
// a dot.
const stagingPrefix = ".fetch-"

// Fetch copies one namespace of a published build (a static mirror or
// another server) into dir/<ns>.
//
// The mirror is not trusted. Every catalog field that becomes part of a
// file name is checked against the protocol patterns before use, and every
// write goes through an os.Root opened on dir, so nothing can land outside
// it (no "..", no absolute path, no symbolic link that leaves dir). The
// files are written to a staging directory first and verified there with
// build.LoadNamespace against a copy of trust; only a namespace that
// verifies replaces dir/<ns>. When anything fails, the staging directory is
// removed and dir/<ns> is left as it was.
func Fetch(ctx context.Context, base, ns, dir string, trust *signing.Trust) error {
	if !signing.ValidNamespace(ns) {
		return fmt.Errorf("namespace %q is not valid", ns)
	}
	if trust == nil {
		return errors.New("fetch needs a trust store to verify the namespace")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	stage, err := stagingName()
	if err != nil {
		return err
	}
	if err := root.Mkdir(stage, 0o700); err != nil {
		return err
	}
	// Always remove the staging directory: after a successful swap it only
	// holds the previous copy of the namespace.
	defer root.RemoveAll(stage)
	staged := path.Join(stage, ns)
	if err := download(ctx, root, staged, base, ns); err != nil {
		return err
	}
	// LoadNamespace takes the namespace from the directory name, so the
	// staged copy lives at <stage>/<ns>. FollowKeyrings advances the trust
	// copy through rotations the mirror carries, each one verified by the
	// keyring before it, exactly as kbd does at start.
	check := trust.Clone()
	stagedPath := filepath.Join(dir, filepath.FromSlash(staged))
	if err := build.FollowKeyrings(stagedPath, check); err != nil {
		return fmt.Errorf("fetched namespace does not verify: %v", err)
	}
	if _, err := build.LoadNamespace(stagedPath, check); err != nil {
		return fmt.Errorf("fetched namespace does not verify: %v", err)
	}
	return swap(root, staged, ns, path.Join(stage, "previous"))
}

// stagingName returns a fresh, unpredictable staging directory name.
func stagingName() (string, error) {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return stagingPrefix + hex.EncodeToString(b), nil
}

// swap moves the verified staged namespace to ns. A current ns (a
// directory, or anything else, such as a symbolic link) is first renamed
// to previous, so a link is replaced, never followed; it is restored when
// the second rename fails.
func swap(root *os.Root, staged, ns, previous string) error {
	hadOld := false
	if _, err := root.Lstat(ns); err == nil {
		if err := root.Rename(ns, previous); err != nil {
			return err
		}
		hadOld = true
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := root.Rename(staged, ns); err != nil {
		if hadOld {
			_ = root.Rename(previous, ns)
		}
		return err
	}
	return nil
}

// localPath turns a slash-separated path from the mirror protocol into a
// path under the staging directory. It refuses anything that is not a
// plain relative path: absolute paths, "..", empty elements and
// backslashes (which are separators on some systems). os.Root enforces the
// same limit again when the file is written.
func localPath(staged, rel string) (string, error) {
	if rel == "" || strings.ContainsAny(rel, "\\\x00") || path.Clean(rel) != rel || !filepath.IsLocal(filepath.FromSlash(rel)) {
		return "", fmt.Errorf("mirror path %q is not a plain relative path", rel)
	}
	return path.Join(staged, rel), nil
}

// writeConfined writes b to rel under staged through root.
func writeConfined(root *os.Root, staged, rel string, b []byte) error {
	p, err := localPath(staged, rel)
	if err != nil {
		return err
	}
	if err := root.MkdirAll(path.Dir(p), 0o755); err != nil {
		return err
	}
	return root.WriteFile(p, b, 0o644)
}

// download copies every file of the namespace from the mirror into staged.
// It reads the unsigned payloads only to learn which files exist, and it
// validates each value that becomes part of a path before using it.
func download(ctx context.Context, root *os.Root, staged, base, ns string) error {
	base = strings.TrimRight(base, "/") + "/kb/v" + protocol.Version + "/" + ns + "/"
	hc := &http.Client{}
	get := func(rel string) ([]byte, error) {
		if _, err := localPath(staged, rel); err != nil {
			return nil, err
		}
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
		return b, writeConfined(root, staged, rel, b)
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
	// Catalog.Validate checks every pack id and version against the
	// protocol patterns and that each path is exactly PackPath(id, version).
	if err := cat.Validate(); err != nil {
		return fmt.Errorf("mirror catalog: %v", err)
	}
	if cat.Namespace != ns {
		return fmt.Errorf("mirror catalog is for namespace %q", cat.Namespace)
	}
	for _, cp := range cat.Packs {
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
