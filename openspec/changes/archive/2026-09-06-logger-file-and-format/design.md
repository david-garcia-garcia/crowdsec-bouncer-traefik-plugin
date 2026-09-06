## Context

`NewWithFormat` is called from `plugin.go` on every Traefik middleware construction. File logging opens with `os.OpenFile` per call. There is no middleware shutdown hook; `pkg/reclaim` is used for LAPI/AppSec clients, not loggers.

## Goals / Non-Goals

**Goals:**
- One open descriptor per distinct log file path for the process lifetime.
- Case-insensitive `"json"` format selection.
- Tests proving both behaviors through `NewWithFormat`.

**Non-Goals:**
- `Close()` API or plugin wiring.
- Configuration validation file open in `pkg/configuration`.
- Normalizing undocumented format strings like `text`.

## Decisions

- **Shared file map:** `sync.Map` keyed by `filepath.Clean(logFilePath)`. `LoadOrStore` on first successful open; close duplicate if racing. Failed opens fall back to stdout (unchanged).
- **Format:** `strings.EqualFold(logFormat, "json")` before handler selection.
- **Lifetime:** Files stay open until process exit; documented in spec as intentional for Traefik plugin reload semantics.

## Risks / Trade-offs

- Shared file handle means concurrent writes from multiple slog handlers to the same path rely on `os.File` and slog concurrency (pre-existing). No change to slog semantics.
- Different paths to the same inode still open separately (acceptable; operators use one canonical path).

## Migration Plan

None — behavior fix only; no config key changes.

## Open Questions

None — explore resolved close vs share in favor of process-lifetime share.
