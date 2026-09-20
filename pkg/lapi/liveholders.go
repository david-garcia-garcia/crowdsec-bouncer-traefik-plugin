package lapi

import (
	"context"
	"sort"
)

// liveHolders is the Client-owned registry of Traefik middleware names
// from each live constructor that bound this Client.
type liveHolders struct {
	nameByCtx map[context.Context]string
}

// register stores this constructor ctx’s Traefik name. Caller holds Client.mu.
func (h *liveHolders) register(ctx context.Context, name string) {
	if h.nameByCtx == nil {
		h.nameByCtx = make(map[context.Context]string)
	}
	h.nameByCtx[ctx] = name
}

// unregister drops this constructor ctx. Caller holds Client.mu.
func (h *liveHolders) unregister(ctx context.Context) {
	delete(h.nameByCtx, ctx)
}

// distinctNames is the sorted set of registered Traefik names. Caller holds Client.mu.
func (h *liveHolders) distinctNames() []string {
	seen := make(map[string]struct{}, len(h.nameByCtx))
	for _, name := range h.nameByCtx {
		seen[name] = struct{}{}
	}
	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
