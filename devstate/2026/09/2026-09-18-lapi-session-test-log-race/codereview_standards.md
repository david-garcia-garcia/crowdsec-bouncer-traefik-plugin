# Standards

1. [judgement] Name for the scope — `pkg/lapi/zzz_logsink_test.go:12` — `syncLogSink` names the mechanism (`sync`) beside the unit (`log sink`); `lockedLogSink` or `safeLogSink` were the alternatives
   → Keep `syncLogSink`: the unit is the sink, `sync` states the invariant that makes it usable from a test, and the devdocs Language entry is `log sink`
   Status: skipped
   Argument: judgement; the debt note proposed `syncWriter`, which is less precise than `syncLogSink` because the type is a `slog` destination, not a general writer.
