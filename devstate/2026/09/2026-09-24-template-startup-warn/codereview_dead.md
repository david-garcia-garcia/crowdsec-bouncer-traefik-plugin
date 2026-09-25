# Dead

1. [hard] Unreachable branch — `pkg/configuration/configuration.go:306` — `TemplateUnavailableReason` compared `err.Error()` to `no template file provided` after `path == ""` already returned `empty`; `GetTemplate` only emits that error when `path` is empty
   Fix: Drop the string match; classify from `path` only (empty path → `empty`, else `unloadable`).
   Status: done
   Argument: Simplified `TemplateUnavailableReason` to path-only; removed dead `err.Error()` branch.
