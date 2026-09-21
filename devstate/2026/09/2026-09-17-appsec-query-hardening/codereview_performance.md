# Performance

1. [hard] Unbounded payload or download — `pkg/appsec/query.go:190` — `io.ReadAll` skips `LimitReader` when `appsecBodyLimit == 0`; client request body size grows two heap copies (`bodyBytes` + `TeeReader` `bodyBuffer`) on `Query`
   → Bound bytes on the copy
   Status: skipped
   Argument: judgement — `appsecBodyLimit` 0 is specified as unlimited (explore resolved, spec, ticket). Bounding it would add a silent cap or a new knob.
