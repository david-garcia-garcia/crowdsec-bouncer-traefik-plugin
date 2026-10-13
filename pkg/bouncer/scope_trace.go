package bouncer

import (
	"log/slog"
	"sort"
)

// appendScopesGroup adds a sorted slog group named scopes to trace attributes.
// An empty map leaves the attributes unchanged, so the trace omits the group.
func appendScopesGroup(attrs []any, scopes map[string]string) []any {
	if len(scopes) == 0 {
		return attrs
	}
	names := make([]string, 0, len(scopes))
	for name := range scopes {
		names = append(names, name)
	}
	sort.Strings(names)
	groupArgs := make([]any, 0, len(names)*2)
	for _, name := range names {
		groupArgs = append(groupArgs, name, scopes[name])
	}
	return append(attrs, slog.Group("scopes", groupArgs...))
}
