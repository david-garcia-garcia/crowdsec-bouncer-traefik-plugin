# Standards

1. [hard] Fix the cause — `pkg/appsec/query.go:126` — Query papers over two `readCappedAppsecBody` failures with `strings.HasPrefix(err.Error(), "appsecQuery:readBody")`; the helper already knew the kind when it formatted the error
   → Return a sentinel or typed error from `readCappedAppsecBody` and match it with `errors.Is` / `errors.As`
   Status: done
   Argument: Query matches `errAppsecReadBody` with `errors.Is`; `readCappedAppsecBody` wraps that sentinel. `Error()` still starts with `appsecQuery:readBody`.
