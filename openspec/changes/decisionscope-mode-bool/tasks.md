## 1. Lookup API

- [ ] 1.1 Change `LookupCachedRemediation` to take `useRangeMembership bool` instead of `mode string`; drop the `configuration` import from `pkg/decisionscope`
- [ ] 1.2 Update `pkg/decisionscope/range_test.go` to pass true/false instead of `"stream"`/`"none"`

## 2. Call site

- [ ] 2.1 `bouncer.ServeHTTP` passes `Mode() == StreamMode || Mode() == AloneMode` into lookup
- [ ] 2.2 Update `knowledge/devdocs/core_plugin_decisionscope.md` snippet to the bool argument

## 3. Verify

- [ ] 3.1 `go test ./pkg/decisionscope/ ./pkg/bouncer/`
- [ ] 3.2 Confirm `pkg/decisionscope` Go files do not import `pkg/configuration`
