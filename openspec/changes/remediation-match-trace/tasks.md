## 1. Remediating TRACE attributes

- [ ] 1.1 In `pkg/bouncer/bouncer.go`, drop `cache` from the remediating store-hit `ServeHTTP` TRACE. Keep `ip` from `req.remoteIP` and `remediation` (letter). Attach present `RequestScopeValues` already in `scopes` as slog group `scopes` (sort keys). Omit the group when the map is empty. Do not call `GetRemoteIP` or `RequestScopeValues` again. Do not re-read headers. Do not add a winner field or a Range CIDR.
- [ ] 1.2 On the remediating `ServeHTTP:LiveLookup` TRACE, keep `ip` and `isBanned`. Attach the same `scopes` group from the map already in hand. Do not add `cache`. Leave `handleRemediationServeHTTP` TRACE as `ip` + `remediation`. Leave DEBUG `ServeHTTP:Get` `cache`.

## 2. Tests

- [ ] 2.1 Extend `pkg/bouncer/zzz_debug_attrs_test.go`: stream store-hit remediating TRACE with mapped Country and AS headers present. Assert `msg=ServeHTTP`, `ip`, `remediation` letter, no `cache`, and group `scopes` with those Country and AS values. Capture with `newTestLogSink`. Seed via `SeedLiveSnapshotForTest`.
- [ ] 2.2 Same file: mapped Country with the Country header missing. Assert the remediating `ServeHTTP` TRACE has no Country key under `scopes`.
- [ ] 2.3 Same file: remediating store hit with no mapped headers. Assert `ip` + `remediation`, no `cache`, no invented scope keys. Keep `TestHunt_ServeHTTPTraceUsesAttributes` for first-breadcrumb `ip` + `isTrusted` without requiring `scopes`.
- [ ] 2.4 Cover remediating `ServeHTTP:LiveLookup` (live mode, empty store so lookup misses, test LAPI ban, mapped headers present). Assert `msg=ServeHTTP:LiveLookup`, `ip`, `isBanned`, present `scopes`, no `cache`. Stay in `pkg/bouncer` with an httptest LAPI, or next to the plugin-root `liveLAPI` fixture if that is the smaller wire-up.

## 3. Leave neighbors

- [ ] 3.1 Do not change `LookupRemediation` / `lookupHits` return. Do not change default `logLevel` or logger file/format. Do not write `knowledge/devdocs` this apply (usage How-to still names DestBranch cache-hit).
- [ ] 3.2 Run `go test ./pkg/bouncer/ -count=1` for the TRACE attribute tests this change touches.
