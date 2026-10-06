// Package source reads a namespace from a content repository: a
// namespace.yaml and one directory per entry, with one Markdown file per
// language. Machine fields (ids, conditions, proposals) live only in the
// English file's front matter; other languages carry only human text.
//
//	<ns>/namespace.yaml
//	<ns>/entries/<id>/en.md       front matter: every field
//	<ns>/entries/<id>/pt-BR.md    front matter: title, summary, proposal_text
package source

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/openbasalt/knowledge/protocol"
	"github.com/openbasalt/knowledge/signing"
)

// PackDef declares a pack in namespace.yaml.
type PackDef struct {
	ID          string              `yaml:"id"`
	AppliesTo   protocol.Conditions `yaml:"applies_to"`
	Title       map[string]string   `yaml:"title"`
	Description map[string]string   `yaml:"description"`
}

// Namespace is namespace.yaml.
type Namespace struct {
	Namespace   string            `yaml:"namespace"`
	Title       map[string]string `yaml:"title"`
	Description map[string]string `yaml:"description"`
	Languages   []string          `yaml:"languages"`
	License     string            `yaml:"license"`
	Actions     []string          `yaml:"actions"`
	Packs       []PackDef         `yaml:"packs"`
}

// enFront is the front matter of the English file.
type enFront struct {
	ID           string               `yaml:"id"`
	Revision     int                  `yaml:"revision"`
	Updated      string               `yaml:"updated"`
	Pack         string               `yaml:"pack"`
	Kind         string               `yaml:"kind"`
	Intents      []string             `yaml:"intents"`
	Components   []string             `yaml:"components"`
	Errors       []string             `yaml:"errors"`
	Keywords     []string             `yaml:"keywords"`
	AppliesTo    protocol.Conditions  `yaml:"applies_to"`
	Proposals    []protocol.Proposal  `yaml:"proposals"`
	References   []protocol.Reference `yaml:"references"`
	Title        string               `yaml:"title"`
	Summary      string               `yaml:"summary"`
	ProposalText map[string]string    `yaml:"proposal_text"`
}

// langFront is the front matter of a translation: human text only.
type langFront struct {
	Title        string            `yaml:"title"`
	Summary      string            `yaml:"summary"`
	ProposalText map[string]string `yaml:"proposal_text"`
}

// Source is a namespace read from disk.
type Source struct {
	Namespace Namespace
	Entries   []*protocol.Entry // sorted by id
}

// Problem is one validation failure, with the file it is about.
type Problem struct {
	File string
	Err  error
}

func (p Problem) String() string { return p.File + ": " + p.Err.Error() }

// Problems collects every failure so a contributor sees all of them at once.
type Problems []Problem

func (ps Problems) Error() string {
	var b strings.Builder
	for i, p := range ps {
		if i > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(p.String())
	}
	return b.String()
}

func decodeYAML(b []byte, v any) error {
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(v); err != nil {
		return err
	}
	return nil
}

// SplitFrontMatter separates the YAML front matter (between two lines of
// three dashes at the top of the file) from the Markdown body.
func SplitFrontMatter(b []byte) ([]byte, string, error) {
	s := strings.ReplaceAll(string(b), "\r\n", "\n")
	if !strings.HasPrefix(s, "---\n") {
		return nil, "", errors.New("missing front matter (the file must start with ---)")
	}
	rest := s[4:]
	end := strings.Index(rest, "\n---\n")
	if end < 0 {
		if strings.HasSuffix(rest, "\n---") {
			return []byte(rest[:len(rest)-4]), "", nil
		}
		return nil, "", errors.New("front matter is not closed with ---")
	}
	return []byte(rest[:end+1]), strings.TrimSpace(rest[end+5:]), nil
}

// Load reads and validates the namespace in dir. All problems are
// returned together.
func Load(dir string) (*Source, error) {
	var probs Problems
	nsFile := filepath.Join(dir, "namespace.yaml")
	b, err := os.ReadFile(nsFile)
	if err != nil {
		return nil, err
	}
	var ns Namespace
	if err := decodeYAML(b, &ns); err != nil {
		return nil, Problems{{nsFile, err}}
	}
	probs = append(probs, checkNamespace(nsFile, &ns)...)

	entriesDir := filepath.Join(dir, "entries")
	des, err := os.ReadDir(entriesDir)
	if err != nil {
		return nil, err
	}
	src := &Source{Namespace: ns}
	for _, de := range des {
		if !de.IsDir() {
			probs = append(probs, Problem{filepath.Join(entriesDir, de.Name()), errors.New("only entry directories belong here")})
			continue
		}
		e, ps := loadEntry(filepath.Join(entriesDir, de.Name()), &ns)
		probs = append(probs, ps...)
		if e != nil {
			src.Entries = append(src.Entries, e)
		}
	}
	sort.Slice(src.Entries, func(i, j int) bool { return src.Entries[i].ID < src.Entries[j].ID })
	if len(probs) > 0 {
		return nil, probs
	}
	return src, nil
}

func checkNamespace(file string, ns *Namespace) Problems {
	var probs Problems
	bad := func(format string, a ...any) { probs = append(probs, Problem{file, fmt.Errorf(format, a...)}) }
	if !signing.ValidNamespace(ns.Namespace) {
		bad("namespace %q is not valid", ns.Namespace)
	}
	if !slices.Contains(ns.Languages, "en") {
		bad("languages must include en")
	}
	for _, l := range ns.Languages {
		if !protocol.ValidLang(l) {
			bad("language %q is not valid", l)
		}
	}
	if ns.License == "" {
		bad("license is required")
	}
	for _, l := range ns.Languages {
		if ns.Title[l] == "" || ns.Description[l] == "" {
			bad("title and description needed in %s", l)
		}
	}
	for _, a := range ns.Actions {
		if !protocol.ValidAction(a) {
			bad("action %q is not an identifier", a)
		}
	}
	seen := map[string]bool{protocol.CorePack: true}
	for _, p := range ns.Packs {
		if !protocol.ValidID(p.ID) || seen[p.ID] {
			bad("pack %q is not valid, repeated or reserved", p.ID)
		}
		seen[p.ID] = true
		for _, l := range ns.Languages {
			if p.Title[l] == "" || p.Description[l] == "" {
				bad("pack %s: title and description needed in %s", p.ID, l)
			}
		}
	}
	return probs
}

func loadEntry(dir string, ns *Namespace) (*protocol.Entry, Problems) {
	var probs Problems
	enFile := filepath.Join(dir, "en.md")
	b, err := os.ReadFile(enFile)
	if err != nil {
		return nil, Problems{{dir, errors.New("en.md is required")}}
	}
	fm, body, err := SplitFrontMatter(b)
	if err != nil {
		return nil, Problems{{enFile, err}}
	}
	var f enFront
	if err := decodeYAML(fm, &f); err != nil {
		return nil, Problems{{enFile, err}}
	}
	if f.ID != filepath.Base(dir) {
		probs = append(probs, Problem{enFile, fmt.Errorf("id %q must equal the directory name %q", f.ID, filepath.Base(dir))})
	}
	pack := f.Pack
	if pack == "" {
		pack = protocol.CorePack
	}
	e := &protocol.Entry{
		Schema: protocol.SchemaEntry, Namespace: ns.Namespace, ID: f.ID, Revision: f.Revision,
		Updated: f.Updated, Pack: pack, Kind: f.Kind, Intents: f.Intents, Components: f.Components,
		Errors: f.Errors, Keywords: f.Keywords, AppliesTo: f.AppliesTo, Proposals: f.Proposals,
		References: f.References, License: ns.License,
		Variants: map[string]protocol.Variant{"en": {Title: f.Title, Summary: f.Summary, Body: body, Proposals: f.ProposalText}},
	}
	known := pack == protocol.CorePack
	for _, p := range ns.Packs {
		known = known || p.ID == pack
	}
	if !known {
		probs = append(probs, Problem{enFile, fmt.Errorf("pack %q is not declared in namespace.yaml", pack)})
	}
	for _, p := range f.Proposals {
		if !slices.Contains(ns.Actions, p.Action) {
			probs = append(probs, Problem{enFile, fmt.Errorf("proposal %s: action %q is not in the namespace's action list", p.ID, p.Action)})
		}
	}

	files, _ := filepath.Glob(filepath.Join(dir, "*.md"))
	for _, file := range files {
		lang := strings.TrimSuffix(filepath.Base(file), ".md")
		if lang == "en" {
			continue
		}
		if !slices.Contains(ns.Languages, lang) {
			probs = append(probs, Problem{file, fmt.Errorf("language %q is not listed in namespace.yaml", lang)})
			continue
		}
		b, err := os.ReadFile(file)
		if err != nil {
			probs = append(probs, Problem{file, err})
			continue
		}
		fm, body, err := SplitFrontMatter(b)
		if err != nil {
			probs = append(probs, Problem{file, err})
			continue
		}
		var lf langFront
		if err := decodeYAML(fm, &lf); err != nil {
			probs = append(probs, Problem{file, fmt.Errorf("%v (only title, summary and proposal_text belong in a translation)", err)})
			continue
		}
		e.Variants[lang] = protocol.Variant{Title: lf.Title, Summary: lf.Summary, Body: body, Proposals: lf.ProposalText}
	}
	if err := e.Validate(); err != nil {
		probs = append(probs, Problem{dir, err})
	}
	return e, probs
}
