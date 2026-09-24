# Explore

## Concepts

The Traefik constructor already owns **which legs Open**. `LapiMode` already lives on the `Config` that `lapi.New` reads (stream ticker, live lookup, metrics). The leftover consumer split is two exported reclaim entry points that do the same Open.

Units this change would touch:

- `openOwnedLeg` — `plugin.go` — production LAPI own-axis; dest branches stream/alone → `lapi.OpenStream`, else `lapi.OpenLive`.
- `OpenStream` / `OpenLive` — `pkg/lapi/session.go` — both Peek/Open the DecisionStore, reclaim on `OwnershipKey`, `New`, hooks, `bindIdentity`. `OpenStream` then calls `noteStreamOwner`.
- `noteStreamOwner` / `streamOwners` — `pkg/lapi/session.go` — process-wide collision index and WARN `crowdsec lapi stream collision`. Mode gate first: returns unless `LapiMode` is stream or alone; empty `LapiKey` also returns before the lock.
- `dropStreamOwner` — `pkg/lapi/client.go` `Close` — already drops the index row. Not a second owner to invent.
- `appsec.Open` / `captcha.Open` — `pkg/appsec/session.go`, `pkg/captcha/session.go` — the single-`Open` pattern this change matches. Out of scope to edit.
- Live catalog — `openspec/specs/core_plugin_lapi_connection/spec.md` (import list and “After OpenStream or OpenLive bind”); `openspec/specs/core_plugin_decisionstore_store/spec.md` (same Traefik `New` ctx as `OpenStream` / `OpenLive`).
- Usage — `knowledge/devdocs/core_plugin_middleware.md`, `core_plugin_lapi_reclaim-key.md`, `core_plugin_lapi_connection.md`, `core_plugin_decisionstore.md`, `std_go_test_log-sink.md`.

```
plugin.go openOwnedLeg (LAPI enabled)
        │
        ├─ dest: stream|alone → lapi.OpenStream
        │         else        → lapi.OpenLive
        │
        ▼ desired (same as appsec.Open / captcha.Open)
   lapi.Open(bindCtx, cfg, log, name, pluginVersion)
        │
        ├─ openDecisionStore
        ├─ reclaim.OpenWithHooks(OwnershipKey)
        ├─ bindIdentity(middlewareName, bindKey)
        └─ noteStreamOwner   ← returns unless stream|alone
```

Call sites that matter: **54** Go consumer calls + **2** definitions + **7** current-contract docs (roots searched: worktree minus `openspec/changes/archive/` and other-run `devstate/`; patterns `OpenStream(` / `OpenLive(` / `lapi.OpenStream` / `lapi.OpenLive`). All migratable here. No operator YAML names these symbols.

| Kind | Count | Where |
|------|-------|--------|
| Production calls | 2 | `plugin.go` `openOwnedLeg` |
| Test calls | 52 | `pkg/lapi/zzz_severance_test.go` 13, `zzz_session_test.go` 29, `zzz_scopeunion_test.go` 1, `zzz_client_stream_overlap_test.go` 3, `zzz_decisionstore_test.go` 6 (`OpenLive`) |
| Definitions | 2 | `pkg/lapi/session.go` |
| Live specs | 2 | `core_plugin_lapi_connection`, `core_plugin_decisionstore_store` |
| Usage packets | 5 | middleware, reclaim-key, connection, decisionstore, `std_go_test_log-sink` |

Reproduce: **not reproduced** as a defect — dest matches the problem statement. Path: read `plugin.go:147-154` (mode branch) and `pkg/lapi/session.go:100-189` (shared reclaim body; `noteStreamOwner` only on `OpenStream`; early return at `session.go:168-170` before `streamOwners` lock). `plugin.go` is the only production caller. Active `openspec/changes/`: none.

Outside facts used: in-tree. No third-party Open contract. Collision WARN text and LAPI mode runtime stay out of scope (`core_plugin_lapi_reclaim-key` already owns the warn).

## Decisions

- Chosen seam: one `lapi.Open` with the same signature as `appsec.Open` / `captcha.Open`. Body is today’s shared reclaim Open plus `noteStreamOwner`. `plugin.go` LAPI case becomes one call; it does not read `LapiMode` to pick an entry point.
- Rejected: keep `OpenStream` / `OpenLive` as aliases — Desired is one `Open`; aliases would keep the consumer split as a public surface.
- Rejected: leave the mode branch in `plugin.go` and only dedupe the body — the constructor would still choose, which is the problem.
- Rejected: change `noteStreamOwner` collision semantics, warn text, or stream/live/none/alone runtime — Out of scope.
- Rejected: change AppSec or captcha `Open`, add config keys, or revalidate `LapiMode` — Out of scope.
- Rejected: rewrite archived OpenSpec change folders or other-run `devstate/` — historical record.
- Live contract: `openspec/specs/core_plugin_lapi_connection/spec.md` (SHALL import `OpenStream`, `OpenLive`; AdoptTransport after those binds). Sibling live mention: `openspec/specs/core_plugin_decisionstore_store/spec.md`. Propose MODIFIED those remaining promises to `Open`. `core_plugin_lapi_reclaim-key` collision SHALL stays. No new spec family. Active `openspec/changes/`: none.

## Open questions

- Q: Do `OpenStream` / `OpenLive` stay as aliases or get removed?
  Rank: bounded asked — existing exported entry points with 54 enumerated consumer calls (roots: worktree minus archive and other-run devstate; patterns OpenStream( / OpenLive(); Desired One lapi.Open
  Decision: assumed — remove both. Tests and `plugin.go` call `Open`. `LapiMode` on the `Config` already passed into `New` keeps stream vs live behavior.
  By: explore

- Q: What is the blast radius of renaming the test entry points under pkg/lapi?
  Rank: bounded asked — 52 test call expressions enumerated in five pkg/lapi zzz test files; Unknowns names this blast radius
  Decision: assumed — retarget those 52 calls to Open. Test function names that mention OpenStream or OpenLive may stay as scenario labels. Do not add a test-only alias.
  By: explore

- Q: Does live/none walking through `noteStreamOwner` have any process-global side effect besides the mode gate?
  Rank: additive asked — Unknowns names this walk; Desired The stream-collision log stays inside lapi
  Decision: resolved — no write. `noteStreamOwner` returns before the mutex and map when mode is not stream or alone (`pkg/lapi/session.go:168-170`), and again when `LapiKey` is empty. `dropStreamOwner` already runs from `Client.Close`. Unified `Open` can always call the helper.
  By: explore

- Q: Who already owns middleware identity, Client key, store identity, client address, Host, or trust hop on this Open path?
  Rank: additive asked — Open already calls bindIdentity; Desired does not change identity
  Decision: resolved — Traefik Yaegi `New(..., name)` owns the middleware string (`bindIdentity` first-wins empty). `lapi.OwnershipKey` owns the Client reclaim key (`sessionKey`). `SessionHex` owns the DecisionStore. `pkg/ip.GetRemoteIP` owns client address on ServeHTTP. Do not reconstruct Host, tenant, user, or trust hop in `Open`. Reuse `bindIdentity` as-is.
  By: explore
