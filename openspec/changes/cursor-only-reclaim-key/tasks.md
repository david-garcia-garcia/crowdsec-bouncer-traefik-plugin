## 1. Reclaim shim

- [ ] 1.1 Import utilities `reclaim` v1.0.3 in the local shim (`Default`, `ProcessGrace` 30s, `Open` / `OpenWithHooks`, `ResetForTest` / `ResetForTestWith`). Delete `pkg/reclaim/table.go` and `pkg/reclaim/peek.go`. Do not take `OpenTyped`
- [ ] 1.2 Point `pkg/appsec/session.go` at the shim only (import + `OpenWithHooks` + type assert). Do not change the AppSec reclaim key. Leave hooks-as-funcs
- [ ] 1.3 Delete `pkg/reclaim/zzz_peek_test.go`. Cover shim exports exist and Peek / View do not

## 2. Client Open key

- [ ] 2.1 Stream/alone Open key is `lapi:stream:` + SessionHex + `:` + hash(`storeParamsFrom`). Drop intervals, `updateMaxFailure`, CAPI scenarios, and `decisionScopeHeaders` from the Client hash
- [ ] 2.2 Live/none Open key is `lapi:` + SessionHex + `:` + hash(`storeParamsFrom`). Keep `IdentityHex` exported if callers still name it. Do not reuse `StoreKey` as the Client string
- [ ] 2.3 Delete `Peek` / `PeekLivePrefix` / warn-and-wire / sleeper retitle from `OpenStream`. Silent first-wins for interval / CAPI / `updateMaxFailure`

## 3. Scope union

- [ ] 3.1 Add a Client-owned live-router header-scope registry keyed by constructor ctx. Register after a successful `OpenStream` bind; unregister on ctx Done. Leave write-once `decisionScopeHeaders`. No `atomic.Pointer[T]`, no `sync.Once`, no package global
- [ ] 3.2 `streamQuery` and `storeStreamDecision` snapshot the union under the existing Client mutex. CAPI still omits `scopes=`. No auto-`startup=true` when the union grows. No sweep when it shrinks

## 4. Tests and upgrade

- [ ] 4.1 Cover: interval mismatch shares one Client (no warn-and-wire); different Redis isolates Client and store; header-map mismatch shares one Client; sleeping interval Wakes the same slot; sleeping Redis host does not overlap pollers
- [ ] 4.2 Cover: two routers union Country and username; unregister drops a scope from the next query; late Country join uses `startup=false`
- [ ] 4.3 Document upgrade: SessionHex and store Redis params stay; Redis keys unchanged; only the in-process Client Open string changes. No Redis migration

## 5. Debt close

- [ ] 5.1 Delete `knowledge/debt/2026-09-17-cursor-only-reclaim-key.md`
- [ ] 5.2 Mark the matching `issues.md` row `[x]` with `Taken:` if that file exists on this run

## 6. Verify

- [ ] 6.1 `go test` for `pkg/lapi`, `pkg/reclaim`, and `pkg/appsec` (import only). Leave `pkg/captcha/` alone
- [ ] 6.2 Grep live product paths (not `openspec/changes/archive/`, not `devstate/`) for `Peek`, `PeekLivePrefix`, `View`, and utilities `reclaim` imported outside the shim
