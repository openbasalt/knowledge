package source

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// seedCopy copies the seed namespace to a temporary directory and
// returns the namespace dir and a directory outside it.
func seedCopy(t *testing.T) (string, string) {
	t.Helper()
	top := t.TempDir()
	ns := filepath.Join(top, "content", "basalt")
	if err := os.CopyFS(ns, os.DirFS("../../content/basalt")); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(top, "outside")
	if err := os.Mkdir(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	return ns, outside
}

// replaceWithLink moves path to outside and leaves a symbolic link to it,
// so the target is valid content: only the link is wrong.
func replaceWithLink(t *testing.T, path, outside string) {
	t.Helper()
	target := filepath.Join(outside, filepath.Base(path))
	if err := os.Rename(path, target); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
}

// Load refuses a symbolic link anywhere in the namespace, even when the
// file it points to is valid content.
func TestLoadRefusesSymlinks(t *testing.T) {
	for _, rel := range []string{
		"entries/nvidia-legacy-580/pt-BR.md",
		"entries/nvidia-legacy-580/en.md",
		"namespace.yaml",
		"entries",
		".",
	} {
		t.Run(rel, func(t *testing.T) {
			ns, outside := seedCopy(t)
			// With and without a trailing slash, as kb validate gets it.
			for _, d := range []string{ns, ns + "/"} {
				if _, err := Load(d); err != nil {
					t.Fatalf("copy does not load: %v", err)
				}
			}
			replaceWithLink(t, filepath.Join(ns, rel), outside)
			_, err := Load(ns)
			if err == nil {
				t.Fatal("symbolic link followed")
			}
			if !errors.Is(err, ErrSymlink) && !containsSymlinkProblem(err) {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func containsSymlinkProblem(err error) bool {
	var probs Problems
	if !errors.As(err, &probs) {
		return false
	}
	for _, p := range probs {
		if errors.Is(p.Err, ErrSymlink) {
			return true
		}
	}
	return false
}

func TestReadNoFollow(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.md"), []byte("ok"), 0o644); err != nil {
		t.Fatal(err)
	}
	if b, err := ReadNoFollow(dir, "a.md"); err != nil || string(b) != "ok" {
		t.Fatalf("%q %v", b, err)
	}
	if err := os.Symlink(filepath.Join(dir, "a.md"), filepath.Join(dir, "b.md")); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadNoFollow(dir, "b.md"); !errors.Is(err, ErrSymlink) {
		t.Fatalf("link: %v", err)
	}
	if _, err := ReadNoFollow(dir, "../x.md"); err == nil {
		t.Fatal("path outside base accepted")
	}
	if _, err := ReadNoFollow(dir, "."); err == nil {
		t.Fatal("directory read as a file")
	}
}
