# Explore
IssueKey: 2026-09-06-logger-file-and-format

## Concepts
- `NewWithFormat` builds a `*slog.Logger` per Traefik middleware `New` call (`plugin.go:26`). File-backed loggers open `LogFilePath` with `os.OpenFile` and never close.
- Traefik Yaegi reload creates new middleware instances; old loggers become unreachable but their FDs stay open until GC/finalizer.
- `logFormat == "json"` is exact-match; `"JSON"` falls through to text handler while `LogLevel` is uppercased in `plugin.go`.
- `pkg/reclaim` provides process-wide keyed lifecycle for LAPI/AppSec clients with `Close()` on grace; logger is created before reclaim and is not a reclaim value today.
- Scope bound: `pkg/logger` (+ tests). No `plugin.go` wiring required for this fix.

## Decisions
- **FD leak:** Share one open `*os.File` per cleaned `LogFilePath` inside `pkg/logger` (process-lifetime map + `LoadOrStore`). Reuse on reload instead of opening a new descriptor each `NewWithFormat`. Do not expose `Close()` or change plugin constructor signature.
- **Format casing:** Select JSON handler with `strings.EqualFold(logFormat, "json")`. All other values keep common/text handler (including undocumented `text`).
- **Tests:** Add `NewWithFormat` tests — uppercase `"JSON"` emits valid JSON; repeated calls with the same temp file path reuse one underlying file (write from two loggers, single file content; no per-call `OpenFile` leak observable via shared writes).
- **Spec:** New leaf `std_go_logger_slog-output` (no existing logger spec in `openspec/specs/map.md`).

## Open questions
- Q: Does Traefik expose a middleware shutdown hook to invoke logger cleanup on reload?
  Decision: assumed — no hook required; process-lifetime shared file handle per path prevents FD accumulation without plugin changes.
  By: explore

- Q: Close-on-reload vs open-once-per-process?
  Decision: resolved — open-once-per-process keyed by path inside `pkg/logger`; documented in spec as intentional process-lifetime handle.
  By: explore
