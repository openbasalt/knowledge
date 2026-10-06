package build_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/openbasalt/knowledge/internal/build"
	"github.com/openbasalt/knowledge/internal/source"
	"github.com/openbasalt/knowledge/internal/testkit"
	"github.com/openbasalt/knowledge/signing"
)

// Two builds of the same content with the same key and time are byte for
// byte identical (reproducible builds).
func TestReproducible(t *testing.T) {
	kit := testkit.New(t, "../../content/basalt", time.Now())
	src, err := source.Load("../../content/basalt")
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC)
	var outs []string
	for range 2 {
		out := t.TempDir()
		if _, err := build.Build(src, build.Options{Out: out, Version: "2026.10.5", Created: at,
			Signer: kit.Publisher, Keyrings: []*signing.Envelope{kit.Keyring}}); err != nil {
			t.Fatal(err)
		}
		outs = append(outs, out)
	}
	err = filepath.Walk(outs[0], func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(outs[0], p)
		a, _ := os.ReadFile(p)
		b, err := os.ReadFile(filepath.Join(outs[1], rel))
		if err != nil || !bytes.Equal(a, b) {
			t.Errorf("%s differs between builds", rel)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestRefusesWrongSigner(t *testing.T) {
	kit := testkit.New(t, "../../content/basalt", time.Now())
	src, _ := source.Load("../../content/basalt")
	for name, s := range map[string]*signing.Signer{"root key": kit.Root, "online key": kit.Online} {
		if _, err := build.Build(src, build.Options{Out: t.TempDir(), Version: "1", Created: time.Now(),
			Signer: s, Keyrings: []*signing.Envelope{kit.Keyring}}); err == nil {
			t.Errorf("%s accepted as publisher", name)
		}
	}
}

func TestLoadRefusesDamage(t *testing.T) {
	kit := testkit.New(t, "../../content/basalt", time.Now())
	// An entry file that differs from its pack.
	p := filepath.Join(kit.Dir, "entries", "journal-disk-usage.json")
	other, _ := os.ReadFile(filepath.Join(kit.Dir, "entries", "nvidia-which-driver.json"))
	if err := os.WriteFile(p, other, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := build.LoadNamespace(kit.Dir, kit.Trust(t)); err == nil {
		t.Fatal("swapped entry file accepted")
	}
	// Another publisher's trust refuses everything.
	other2 := testkit.New(t, "../../content/basalt", time.Now())
	if _, err := build.LoadNamespace(other2.Dir, kit.Trust(t)); err == nil {
		t.Fatal("content of an untrusted publisher accepted")
	}
}

// The committed sample build verifies against its own trust file.
func TestSample(t *testing.T) {
	tr, err := signing.LoadTrust("../../examples/sample/trust.json")
	if err != nil {
		t.Fatal(err)
	}
	n, err := build.LoadNamespace("../../examples/sample/kb/v0/basalt", tr)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := n.Packs["nvidia-legacy-580"]; !ok {
		t.Fatal("sample pack missing")
	}
}
