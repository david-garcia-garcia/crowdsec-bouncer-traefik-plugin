## Why

Matching (`pkg/decisionscope`) imports the Traefik plugin config bag only to compare Crowdsec mode strings before consulting Range membership. That domain should not know Traefik config constants.

## What Changes

- `LookupCachedRemediation` takes `useRangeMembership bool` instead of a mode string. Callers that already know the mode pass true for stream and alone.
- `pkg/decisionscope` no longer imports `pkg/configuration`.
- ServeHTTP and tests pass the bool. Membership argument stays.
- **Not BREAKING** for operators: no YAML, no runtime Range behavior change.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `core_plugin_decisions_scopes`: Request lookup takes a caller bool for Range membership. `pkg/decisionscope` MUST NOT import `pkg/configuration`. Stream/alone still use membership; live/none still skip it.

## Impact

- `pkg/decisionscope/lookup.go` signature and import.
- `pkg/decisionscope/range_test.go` call sites.
- `pkg/bouncer/bouncer.go` ServeHTTP call site.
- Usage packet `knowledge/devdocs/core_plugin_decisionscope.md` snippet.
