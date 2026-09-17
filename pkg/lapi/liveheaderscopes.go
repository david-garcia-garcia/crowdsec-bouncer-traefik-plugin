package lapi

import "context"

// liveHeaderScopes is the Client-owned registry of normalized header-scope maps
// from each live constructor that bound this Client.
type liveHeaderScopes struct {
	headerScopesByCtx map[context.Context]map[string]string
}

// register stores this constructor ctx’s header map. Caller holds Client.mu.
func (r *liveHeaderScopes) register(ctx context.Context, headers map[string]string) {
	if r.headerScopesByCtx == nil {
		r.headerScopesByCtx = make(map[context.Context]map[string]string)
	}
	copied := make(map[string]string, len(headers))
	for scope, header := range headers {
		copied[scope] = header
	}
	r.headerScopesByCtx[ctx] = copied
}

// unregister drops this constructor ctx. Caller holds Client.mu.
func (r *liveHeaderScopes) unregister(ctx context.Context) {
	delete(r.headerScopesByCtx, ctx)
}

// union is the merged header-scope map of every registered constructor. Caller holds Client.mu.
func (r *liveHeaderScopes) union() map[string]string {
	out := make(map[string]string)
	for _, headers := range r.headerScopesByCtx {
		for scope, header := range headers {
			out[scope] = header
		}
	}
	return out
}
