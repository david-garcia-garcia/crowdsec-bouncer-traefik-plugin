package lapi

import "context"

// liveHeaderScopes is the Client-owned registry of normalized header-scope maps
// from each live constructor that bound this Client.
type liveHeaderScopes struct {
	holders map[context.Context]map[string]string
}

// register stores this constructor ctx’s header map. Caller holds Client.mu.
func (r *liveHeaderScopes) register(ctx context.Context, headers map[string]string) {
	if r.holders == nil {
		r.holders = make(map[context.Context]map[string]string)
	}
	copied := make(map[string]string, len(headers))
	for scope, header := range headers {
		copied[scope] = header
	}
	r.holders[ctx] = copied
}

// unregister drops this constructor ctx. Caller holds Client.mu.
func (r *liveHeaderScopes) unregister(ctx context.Context) {
	delete(r.holders, ctx)
}

// union is the merged header-scope map of every live holder. Caller holds Client.mu.
func (r *liveHeaderScopes) union() map[string]string {
	out := make(map[string]string)
	for _, headers := range r.holders {
		for scope, header := range headers {
			out[scope] = header
		}
	}
	return out
}
