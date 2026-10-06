package review

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/openbasalt/knowledge/internal/source"
)

// Config of one review run.
type Config struct {
	Provider Provider
	Model    string
	Tier     string // pr or release
	Rules    string // the rules file
	Actions  []string
	MaxBatch int // bytes of content per request (default 120000)
}

// Run reviews the units in batches and merges the verdicts. Any provider
// error or unparsable answer is an error: the check fails closed.
func Run(ctx context.Context, cfg Config, units []Unit) (*Verdict, error) {
	if len(units) == 0 {
		return &Verdict{Verdict: "pass", Summary: "No content changed."}, nil
	}
	if cfg.MaxBatch == 0 {
		cfg.MaxBatch = 120000
	}
	system := SystemPrompt(cfg.Rules)
	var vs []*Verdict
	for _, batch := range Batches(units, cfg.MaxBatch) {
		var ids []string
		for _, u := range batch {
			ids = append(ids, u.ID)
		}
		answer, err := cfg.Provider.Complete(ctx, cfg.Model, system, UserPrompt(cfg.Tier, cfg.Actions, batch))
		if err != nil {
			return nil, fmt.Errorf("%s: %v", cfg.Provider.Name(), err)
		}
		v, err := ParseVerdict(answer, ids)
		if err != nil {
			return nil, err
		}
		vs = append(vs, v)
	}
	return Merge(vs), nil
}

// Overview is the release tier's consistency unit: every entry of the
// namespace in one compact listing (ids, packs, conditions, proposals,
// titles), so the reviewer can spot contradictions, duplicates and
// conditions that do not match the text.
func Overview(src *source.Source) Unit {
	var b strings.Builder
	fmt.Fprintf(&b, "namespace: %s\nactions: %s\n", src.Namespace.Namespace, strings.Join(src.Namespace.Actions, ", "))
	for _, p := range src.Namespace.Packs {
		cond, _ := json.Marshal(p.AppliesTo)
		fmt.Fprintf(&b, "pack %s applies_to=%s title=%q\n", p.ID, cond, p.Title["en"])
	}
	for _, e := range src.Entries {
		cond, _ := json.Marshal(e.AppliesTo)
		props, _ := json.Marshal(e.Proposals)
		fmt.Fprintf(&b, "\nentry %s rev %d pack %s kind %s\n  intents=%v components=%v errors=%v\n  applies_to=%s\n  proposals=%s\n",
			e.ID, e.Revision, e.Pack, e.Kind, e.Intents, e.Components, e.Errors, cond, props)
		for lang, v := range e.Variants {
			fmt.Fprintf(&b, "  title[%s]=%q\n", lang, v.Title)
		}
	}
	id := src.Namespace.Namespace + "/bundle"
	return Unit{ID: id, Files: []File{{Path: "(generated overview of " + src.Namespace.Namespace + ")", Content: b.String()}}}
}
