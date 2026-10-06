package source

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The seed content of the repository must always validate.
func TestSeedContent(t *testing.T) {
	src, err := Load("../../content/basalt")
	if err != nil {
		t.Fatal(err)
	}
	if len(src.Entries) < 5 {
		t.Fatalf("%d entries", len(src.Entries))
	}
	for _, e := range src.Entries {
		for _, l := range src.Namespace.Languages {
			if _, ok := e.Variants[l]; !ok {
				t.Errorf("%s: no %s variant", e.ID, l)
			}
		}
	}
}

func writeEntry(t *testing.T, root, id, en, pt string) {
	t.Helper()
	dir := filepath.Join(root, "entries", id)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "en.md"), []byte(en), 0o644); err != nil {
		t.Fatal(err)
	}
	if pt != "" {
		if err := os.WriteFile(filepath.Join(dir, "pt-BR.md"), []byte(pt), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

const nsYAML = `namespace: test
title: {en: T, pt-BR: T}
description: {en: D, pt-BR: D}
languages: [en, pt-BR]
license: Apache-2.0
actions: [unit.restart]
`

const goodEN = `---
id: one
revision: 1
updated: "2026-10-05"
kind: fix
proposals:
  - {id: restart, action: unit.restart, params: {unit: nginx.service}, risk: low}
title: Title
summary: Summary
proposal_text: {restart: Restart nginx.}
---
Body.
`

func TestRules(t *testing.T) {
	cases := []struct {
		name, en, pt, want string
	}{
		{"good", goodEN, "---\ntitle: T\nsummary: S\nproposal_text: {restart: R}\n---\nCorpo.\n", ""},
		{"machine field in translation", goodEN, "---\ntitle: T\nsummary: S\nkind: fix\nproposal_text: {restart: R}\n---\nB\n", "only title, summary"},
		{"missing proposal text", goodEN, "---\ntitle: T\nsummary: S\n---\nB\n", "no text for proposal restart"},
		{"unknown action", strings.Replace(goodEN, "unit.restart", "shell.run", 1), "", "not in the namespace's action list"},
		{"undeclared pack", strings.Replace(goodEN, "kind: fix", "kind: fix\npack: other", 1), "", "not declared"},
		{"id mismatch", strings.Replace(goodEN, "id: one", "id: two", 1), "", "directory name"},
		{"unknown field", strings.Replace(goodEN, "kind: fix", "kind: fix\ncolor: red", 1), "", "not found"},
		{"no front matter", "Body only\n", "", "front matter"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := t.TempDir()
			if err := os.WriteFile(filepath.Join(root, "namespace.yaml"), []byte(nsYAML), 0o644); err != nil {
				t.Fatal(err)
			}
			writeEntry(t, root, "one", c.en, c.pt)
			_, err := Load(root)
			if c.want == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("want %q, got %v", c.want, err)
			}
		})
	}
}
