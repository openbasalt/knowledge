package mcp

import (
	"context"
	"errors"
	"fmt"

	"github.com/openbasalt/knowledge/client"
	"github.com/openbasalt/knowledge/internal/build"
	"github.com/openbasalt/knowledge/internal/index"
	"github.com/openbasalt/knowledge/protocol"
)

// Remote answers through a server with the verifying client library.
type Remote struct{ Client *client.Client }

// Search implements Backend.
func (r Remote) Search(ctx context.Context, req protocol.SearchRequest) ([]Hit, []protocol.PackRef, error) {
	res, err := r.Client.Search(ctx, req)
	if err != nil {
		return nil, nil, err
	}
	var hits []Hit
	for _, h := range res.Hits {
		hits = append(hits, Hit{Entry: h.Entry, Score: h.Score, Matched: h.Matched})
	}
	return hits, res.Packs, nil
}

// Entry implements Backend.
func (r Remote) Entry(ctx context.Context, ns, id string) (*protocol.Entry, error) {
	return r.Client.Entry(ctx, ns, id)
}

// Catalog implements Backend.
func (r Remote) Catalog(ctx context.Context, ns string) (*protocol.Catalog, error) {
	return r.Client.Catalog(ctx, ns)
}

// Local answers from verified namespaces on disk, offline.
type Local struct {
	ns map[string]*localNS
}

type localNS struct {
	data *build.Namespace
	ix   *index.Index
}

// NewLocal indexes verified namespaces.
func NewLocal(nss ...*build.Namespace) *Local {
	l := &Local{ns: map[string]*localNS{}}
	for _, n := range nss {
		var entries []*protocol.Entry
		for _, e := range n.Entries {
			entries = append(entries, e.Entry)
		}
		l.ns[n.Name] = &localNS{data: n, ix: index.New(entries)}
	}
	return l
}

func (l *Local) get(ns string) (*localNS, error) {
	n := l.ns[ns]
	if n == nil {
		return nil, fmt.Errorf("namespace %q is not loaded", ns)
	}
	return n, nil
}

// Search implements Backend.
func (l *Local) Search(_ context.Context, req protocol.SearchRequest) ([]Hit, []protocol.PackRef, error) {
	req.Schema = protocol.SchemaRequest
	req.Nonce = client.NewNonce()
	if err := req.Validate(); err != nil {
		return nil, nil, err
	}
	n, err := l.get(req.Namespace)
	if err != nil {
		return nil, nil, err
	}
	var hits []Hit
	packs := map[string]bool{}
	for _, h := range n.ix.Search(&req) {
		hits = append(hits, Hit{Entry: h.Entry, Score: h.Score, Matched: h.Matched})
		packs[h.Entry.Pack] = true
	}
	var refs []protocol.PackRef
	for _, cp := range n.data.Catalog.Packs {
		if cp.ID != protocol.CorePack && packs[cp.ID] {
			refs = append(refs, protocol.PackRef{ID: cp.ID, Version: cp.Version, Digest: cp.Digest})
		}
	}
	return hits, refs, nil
}

// Entry implements Backend.
func (l *Local) Entry(_ context.Context, ns, id string) (*protocol.Entry, error) {
	n, err := l.get(ns)
	if err != nil {
		return nil, err
	}
	e := n.data.Entries[id]
	if e == nil {
		return nil, errors.New("no such entry")
	}
	return e.Entry, nil
}

// Catalog implements Backend.
func (l *Local) Catalog(_ context.Context, ns string) (*protocol.Catalog, error) {
	n, err := l.get(ns)
	if err != nil {
		return nil, err
	}
	return n.data.Catalog, nil
}
