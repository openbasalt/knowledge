// Package index is the in-memory search over verified entries: structured
// filtering by applicability conditions (the same Match clients use), a
// small Okapi BM25 over the entry text, and boosts for exact structured
// matches (intent, component, error code, hardware). It is deterministic:
// the same entries and query always give the same ranking.
package index

import (
	"math"
	"slices"
	"sort"
	"strings"
	"unicode"

	"github.com/openbasalt/knowledge/protocol"
)

// BM25 parameters.
const (
	k1 = 1.2
	b  = 0.75
)

// Boosts for exact structured matches.
const (
	boostIntent    = 4.0
	boostComponent = 3.0
	boostError     = 6.0
	boostHardware  = 5.0
	boostPackages  = 2.0
	boostContext   = 0.5 // distro, release, arch
)

type doc struct {
	entry *protocol.Entry
	tf    map[string]int
	len   int
}

// Index searches a fixed set of entries.
type Index struct {
	docs  []doc
	df    map[string]int
	avgdl float64
}

// Hit is one ranked entry.
type Hit struct {
	Entry   *protocol.Entry
	Score   float64
	Matched []string
}

// New indexes the entries.
func New(entries []*protocol.Entry) *Index {
	ix := &Index{df: map[string]int{}}
	sorted := slices.Clone(entries)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].ID < sorted[j].ID })
	total := 0
	for _, e := range sorted {
		d := doc{entry: e, tf: map[string]int{}}
		add := func(s string, weight int) {
			for _, t := range Tokens(s) {
				d.tf[t] += weight
				d.len += weight
			}
		}
		for _, k := range e.Keywords {
			add(k, 3)
		}
		for _, s := range slices.Concat(e.Intents, e.Components, e.Errors) {
			add(s, 2)
		}
		for _, v := range e.Variants {
			add(v.Title, 2)
			add(v.Summary, 1)
			add(v.Body, 1)
		}
		for t := range d.tf {
			ix.df[t]++
		}
		total += d.len
		ix.docs = append(ix.docs, d)
	}
	if len(ix.docs) > 0 {
		ix.avgdl = float64(total) / float64(len(ix.docs))
	}
	return ix
}

// Len returns the number of indexed entries.
func (ix *Index) Len() int { return len(ix.docs) }

// Search ranks the entries for a validated request. Entries whose
// conditions exclude the query's facts are never returned, and an entry
// needs some relevance (text, intent, component, error code, hardware or
// package match) to be returned at all.
func (ix *Index) Search(r *protocol.SearchRequest) []Hit {
	facts := protocol.FactsOf(r)
	terms := queryTerms(r)
	limit := r.Limit
	if limit == 0 {
		limit = protocol.DefaultResults
	}
	var hits []Hit
	n := float64(len(ix.docs))
	for _, d := range ix.docs {
		m := d.entry.AppliesTo.Match(facts)
		if m.Excluded {
			continue
		}
		score := 0.0
		for _, t := range terms {
			tf := float64(d.tf[t])
			if tf == 0 {
				continue
			}
			df := float64(ix.df[t])
			idf := math.Log(1 + (n-df+0.5)/(df+0.5))
			score += idf * tf * (k1 + 1) / (tf + k1*(1-b+b*float64(d.len)/ix.avgdl))
		}
		matched := []string{}
		if score > 0 {
			matched = append(matched, "text")
		}
		if r.Intent != "" && slices.Contains(d.entry.Intents, r.Intent) {
			score += boostIntent
			matched = append(matched, "intent")
		}
		if r.Component != "" && slices.Contains(d.entry.Components, r.Component) {
			score += boostComponent
			matched = append(matched, "component")
		}
		errs := 0
		for _, e := range r.Errors {
			if slices.Contains(d.entry.Errors, e) {
				errs++
			}
		}
		if errs > 0 {
			score += boostError * float64(errs)
			matched = append(matched, "errors")
		}
		relevant := score > 0
		for _, g := range m.Matched {
			switch g {
			case "hardware":
				score += boostHardware
				relevant = true
			case "packages":
				score += boostPackages
				relevant = true
			default:
				score += boostContext
			}
			matched = append(matched, g)
		}
		if !relevant {
			continue
		}
		hits = append(hits, Hit{Entry: d.entry, Score: math.Round(score*1000) / 1000, Matched: matched})
	}
	sort.SliceStable(hits, func(i, j int) bool {
		if hits[i].Score != hits[j].Score {
			return hits[i].Score > hits[j].Score
		}
		return hits[i].Entry.ID < hits[j].Entry.ID
	})
	if len(hits) > limit {
		hits = hits[:limit]
	}
	return hits
}

func queryTerms(r *protocol.SearchRequest) []string {
	var parts []string
	parts = append(parts, r.Intent, r.Component)
	parts = append(parts, r.Errors...)
	for _, p := range r.Packages {
		parts = append(parts, p.Name)
	}
	if r.FreeText != nil {
		parts = append(parts, r.FreeText.Text)
	}
	seen := map[string]bool{}
	var out []string
	for _, p := range parts {
		for _, t := range Tokens(p) {
			if !seen[t] {
				seen[t] = true
				out = append(out, t)
			}
		}
	}
	return out
}

var stop = map[string]bool{
	"the": true, "and": true, "for": true, "with": true, "you": true, "your": true, "this": true, "that": true,
	"is": true, "are": true, "to": true, "of": true, "in": true, "on": true, "it": true, "an": true, "or": true,
	"de": true, "da": true, "do": true, "das": true, "dos": true, "em": true, "um": true, "uma": true, "para": true,
	"com": true, "que": true, "na": true, "no": true, "se": true, "os": true, "as": true, "por": true, "meu": true, "minha": true,
}

// fold maps common Latin accented letters to their base letter, so "vídeo"
// and "video" are the same term.
var fold = strings.NewReplacer(
	"á", "a", "à", "a", "â", "a", "ã", "a", "ä", "a",
	"é", "e", "ê", "e", "è", "e", "ë", "e",
	"í", "i", "î", "i", "ì", "i", "ï", "i",
	"ó", "o", "ô", "o", "õ", "o", "ò", "o", "ö", "o",
	"ú", "u", "û", "u", "ù", "u", "ü", "u",
	"ç", "c", "ñ", "n",
)

// Tokens splits text into lower case terms of two or more letters or
// digits, without accents and common stop words.
func Tokens(s string) []string {
	s = fold.Replace(strings.ToLower(s))
	f := strings.FieldsFunc(s, func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) })
	out := f[:0]
	for _, t := range f {
		if len(t) >= 2 && !stop[t] {
			out = append(out, t)
		}
	}
	return out
}
