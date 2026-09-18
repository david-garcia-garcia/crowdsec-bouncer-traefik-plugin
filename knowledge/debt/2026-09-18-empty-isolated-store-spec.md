# The isolated-store spec is a stub, so the catalog cannot pass strict validation

IssueKey: 2026-09-18-lapi-scope-failclosed-query-hardening
Size: small
Action: note

## Why this follow-up
`openspec/specs/core_cache_client_isolated-store/spec.md` carries a `## Purpose` and nothing else. `openspec validate --specs --strict` therefore reports `26 passed, 1 failed` on the whole catalog, and has done so since before this ticket: `git show origin/master:openspec/specs/core_cache_client_isolated-store/spec.md` has the same single heading at `0e7dbf0`.

Measured while archiving this change. The three deltas this ticket synced (`core_plugin_lapi_failure-action`, `core_plugin_lapi_stream-lease`, and the new `core_plugin_lapi_query-round-trip`) all validate, and `validate-spec-map.mjs` and `validate-artifact-names.mjs` both exit 0. The one failure is unrelated to this diff.

## Proposed shape
Write the requirement the folder name already claims: what "isolated store" means for `cache.Client` key prefixing, and one scenario per store kind. The behavior exists in `pkg/cache` and in `knowledge/devdocs/core_cache_client.md`; only the spec block is missing. The alternative, deleting the folder, loses a real family leaf that `map.md` and the DecisionStore spec both lean on.

## Why it was not taken
Out of this ticket's diff, and `skill:sbs-dev-commandments:Bound the ask`. Filling it in would mean writing requirements for a subsystem this change never touched, and getting them wrong is worse than leaving the stub visible.

## Risks
`openspec validate --specs --strict` stays red, so it cannot be used as a gate that means anything until this one file is filled. Anyone adding it to CI will have to fix this first.
