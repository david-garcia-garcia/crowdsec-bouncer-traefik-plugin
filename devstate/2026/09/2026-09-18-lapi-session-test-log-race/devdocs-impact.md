# Devdocs impact
change: lapi-session-test-log-sink

## Units
- Test log sink — test pattern — `pkg/lapi/zzz_logsink_test.go` (new packet: `knowledge/devdocs/std_go_test_log-sink.md`)
- zzz_ test file — test pattern — `knowledge/devdocs/std_go_test_zzz-prefix.md` (neighbor; filename rule unchanged, the new file follows it)
- LAPI connection — subsystem — `knowledge/devdocs/core_plugin_lapi_connection.md` (read: `New` spawns the metrics goroutine; no usage text changed, production untouched)
- LAPI usage metrics — subsystem — `knowledge/devdocs/core_plugin_lapi_usage-metrics.md` (read: which lines the metrics path logs; no usage text changed)

## Findings
1. Missing packet — the house rule "capture `slog` through a mutex-guarded sink and stop the component before reading" had no usage doc, and `std_go_test_zzz-prefix.md` covers only filenames.
   → Wrote `knowledge/devdocs/std_go_test_log-sink.md` (Language: log sink, leaked ticker; usage; snippet; key files; Gotchas) and added its row to `knowledge/devdocs/index_std_go.md`.
   Status: done
   Argument: new packet plus domain-index row in the same edit; `std` / `go` was already on `knowledge/devdocs/domains.md`, so no allowlist change.
