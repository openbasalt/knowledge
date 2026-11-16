package source

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// ErrSymlink is returned for content paths that are, or pass through, a
// symbolic link. Content comes from pull requests, including forks whose
// review runs next to model API keys, so a link could point at any file of
// the machine that reads it. Links are never followed.
var ErrSymlink = errors.New("symbolic links are not allowed in content")

// CheckNoSymlinks verifies that every component of rel under base exists
// and is not a symbolic link. base itself is trusted (it is chosen by the
// caller, not by the content).
func CheckNoSymlinks(base, rel string) (os.FileInfo, error) {
	rel = filepath.Clean(rel)
	if rel == "." {
		return os.Lstat(base)
	}
	if !filepath.IsLocal(rel) {
		return nil, fmt.Errorf("%s: path leaves %s", rel, base)
	}
	cur := base
	parts := strings.Split(filepath.ToSlash(rel), "/")
	var fi os.FileInfo
	for i, p := range parts {
		cur = filepath.Join(cur, p)
		var err error
		if fi, err = os.Lstat(cur); err != nil {
			return nil, err
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("%s: %w", cur, ErrSymlink)
		}
		if i < len(parts)-1 && !fi.IsDir() {
			return nil, fmt.Errorf("%s: not a directory", cur)
		}
	}
	return fi, nil
}

// ReadNoFollow reads the regular file rel under base, refusing symbolic
// links in any component of rel and anything that is not a regular file
// (devices, pipes). The opened file must be the one that was checked, so a
// swap between the check and the open is refused too.
func ReadNoFollow(base, rel string) ([]byte, error) {
	fi, err := CheckNoSymlinks(base, rel)
	if err != nil {
		return nil, err
	}
	p := filepath.Join(base, rel)
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: not a regular file", p)
	}
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	got, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !os.SameFile(fi, got) {
		return nil, fmt.Errorf("%s: changed while it was read", p)
	}
	return io.ReadAll(f)
}
