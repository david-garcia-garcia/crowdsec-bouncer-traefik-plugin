package lapi

import (
	"context"
	"sort"
)

// liveMiddlewareNames is the Client-owned registry of Traefik middleware names
// from each live constructor that bound this Client.
type liveMiddlewareNames struct {
	nameByCtx map[context.Context]string
}

// register stores this constructor ctx’s Traefik name. Caller holds Client.mu.
func (names *liveMiddlewareNames) register(ctx context.Context, middlewareName string) {
	if names.nameByCtx == nil {
		names.nameByCtx = make(map[context.Context]string)
	}
	names.nameByCtx[ctx] = middlewareName
}

// unregister drops this constructor ctx. Caller holds Client.mu.
func (names *liveMiddlewareNames) unregister(ctx context.Context) {
	delete(names.nameByCtx, ctx)
}

// distinctNames is the sorted set of registered Traefik names. Caller holds Client.mu.
func (names *liveMiddlewareNames) distinctNames() []string {
	seen := make(map[string]struct{}, len(names.nameByCtx))
	for _, middlewareName := range names.nameByCtx {
		seen[middlewareName] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for middlewareName := range seen {
		out = append(out, middlewareName)
	}
	sort.Strings(out)
	return out
}
