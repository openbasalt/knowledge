package protocol

import (
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/openbasalt/knowledge/signing"
)

// OpenEntry verifies an entry envelope against the namespace's publisher
// keys, decodes it strictly and validates it. It also returns the entry's
// digest (the content address of its payload).
func OpenEntry(t *signing.Trust, env *signing.Envelope, ns string) (*Entry, string, error) {
	b, err := t.OpenPublisher(env, ns, TypeEntry)
	if err != nil {
		return nil, "", fmt.Errorf("entry: %v", err)
	}
	var e Entry
	if err := DecodeStrict(b, &e); err != nil {
		return nil, "", fmt.Errorf("entry: %v", err)
	}
	if err := e.Validate(); err != nil {
		return nil, "", fmt.Errorf("entry %s: %v", e.ID, err)
	}
	if e.Namespace != ns {
		return nil, "", fmt.Errorf("entry %s: namespace %q, want %q", e.ID, e.Namespace, ns)
	}
	return &e, signing.DigestBytes(b), nil
}

// OpenPack verifies a pack and every entry in it. Every entry must belong
// to the pack.
func OpenPack(t *signing.Trust, env *signing.Envelope, ns string) (*Pack, []*Entry, error) {
	b, err := t.OpenPublisher(env, ns, TypePack)
	if err != nil {
		return nil, nil, fmt.Errorf("pack: %v", err)
	}
	var p Pack
	if err := DecodeStrict(b, &p); err != nil {
		return nil, nil, fmt.Errorf("pack: %v", err)
	}
	if err := p.Validate(); err != nil {
		return nil, nil, err
	}
	if p.Namespace != ns {
		return nil, nil, fmt.Errorf("pack %s: namespace %q, want %q", p.ID, p.Namespace, ns)
	}
	seen := map[string]bool{}
	var entries []*Entry
	for _, ee := range p.Entries {
		e, _, err := OpenEntry(t, ee, ns)
		if err != nil {
			return nil, nil, fmt.Errorf("pack %s: %v", p.ID, err)
		}
		if e.Pack != p.ID {
			return nil, nil, fmt.Errorf("pack %s: entry %s belongs to pack %s", p.ID, e.ID, e.Pack)
		}
		if seen[e.ID] {
			return nil, nil, fmt.Errorf("pack %s: entry %s twice", p.ID, e.ID)
		}
		seen[e.ID] = true
		entries = append(entries, e)
	}
	return &p, entries, nil
}

// OpenCatalog verifies a catalog and returns it with its digest.
func OpenCatalog(t *signing.Trust, env *signing.Envelope, ns string) (*Catalog, string, error) {
	b, err := t.OpenPublisher(env, ns, TypeCatalog)
	if err != nil {
		return nil, "", fmt.Errorf("catalog: %v", err)
	}
	var c Catalog
	if err := DecodeStrict(b, &c); err != nil {
		return nil, "", fmt.Errorf("catalog: %v", err)
	}
	if err := c.Validate(); err != nil {
		return nil, "", err
	}
	if c.Namespace != ns {
		return nil, "", fmt.Errorf("catalog namespace %q, want %q", c.Namespace, ns)
	}
	return &c, signing.DigestBytes(b), nil
}

// Text returns the variant for lang, falling back to the base language
// (pt for pt-BR) and then to English.
func (e *Entry) Text(lang string) (Variant, string) {
	if v, ok := e.Variants[lang]; ok {
		return v, lang
	}
	base, _, _ := strings.Cut(lang, "-")
	if v, ok := e.Variants[base]; ok && base != "" {
		return v, base
	}
	for _, l := range slices.Sorted(maps.Keys(e.Variants)) {
		if base != "" && strings.HasPrefix(l, base+"-") {
			return e.Variants[l], l
		}
	}
	return e.Variants["en"], "en"
}
