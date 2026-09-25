# Explore

## Concepts

A captcha owner `New` builds one `*slog.Logger` from the three log knobs and passes it into `captcha.Open`. The reclaim table keys that Client by `OwnershipKey`, which today hashes middleware name plus instance-owned captcha knobs and **omits** those log knobs. `newOwnerClient` stores the constructor logger on `Client.log`; `bindIdentity` does not replace it. A log-config-only rebuild therefore Wakes the same incarnation and keeps the old level.

Units this change would touch:

- `ownership` / `ownershipFrom` / `OwnershipKey` — `pkg/captcha/session.go` — captcha Open-key payload. Job: hash middleware name plus instance-owned knobs into `captcha:owner:<hex>`.
- `Open` / `newOwnerClient` — `pkg/captcha/session.go` — reclaim create vs Wake. Job: `create` runs only on miss; reclaim returns the stored `*Client`.
- `Client.New` / `bindIdentity` — `pkg/captcha/captcha.go` — freeze `c.log` at create; bindIdentity first-wins middleware name and sessionKey only.
- `plugin.go` `New` / `openOwnedLeg` / `claimOwnedLeg` — build `log` from `LogLevel` / `LogFilePath` / `LogFormat`, `captcha.Open`, `SetAlias(OwnershipKey, alias:captcha:<name>)`.
- `reclaim.SetAlias` / `Watch` — vendored table + `pkg/reclaim/default.go` — remap the instance alias when the Open key changes; watchers are weak.
- Live catalog — `openspec/specs/core_plugin_middleware_instance-slots/spec.md` (captcha ownership SHALL list).
- Usage — `knowledge/devdocs/core_plugin_middleware.md`, `core_plugin_middleware_instance-slots.md`, `std_go_reclaim.md`, `std_go_logger_nested.md`.
- Out of scope siblings — `pkg/lapi/identity.go` `ownership`, `pkg/appsec/session.go` `identity` (same omit; observe only).

```
plugin.go New
  LogLevel = ToUpper
  log = logger.NewWithFormat(LogLevel, LogFilePath, LogFormat)
        │
        ▼
captcha.Open(bindCtx, cfg, log, name)
        ├─ bindKey = OwnershipKey  (dest: no log knobs)
        └─ reclaim.OpenWithHooks(bindKey)
              create → newOwnerClient → Client.New sets c.log
              reclaim → bindIdentity; c.log unchanged
        │
        ▼
SetAlias(bindKey, alias:captcha:<instance>)
Watch(alias) → bouncer.ReceiveCaptcha
```

Call sites that matter: **2** production `captcha.OwnershipKey` uses + **2** test assertions + **1** live SHALL + **2** usage packets (roots searched: worktree `pkg/`, `plugin.go`, `openspec/specs/`, `knowledge/devdocs/`; patterns `captcha.OwnershipKey`, `OwnershipKey(` in `pkg/captcha`, `instance-owned captcha knobs`). Archive folders and other-run `devstate/` are historical. All migratable here.

| Kind | Count | Where |
|------|-------|--------|
| Production key uses | 2 | `pkg/captcha/session.go` `Open`; `plugin.go` `claimOwnedLeg` |
| Production `captcha.Open` | 1 | `plugin.go` `openOwnedLeg` |
| Test key assertions | 2 | `pkg/captcha/zzz_owner_test.go` (`ExcludesSlotAndBounce`, `EnterpriseKnobChangeReclaims`) |
| Live spec SHALL | 1 | `core_plugin_middleware_instance-slots` |
| Usage packets | 2 | `core_plugin_middleware.md` (Language + Gotchas), `core_plugin_middleware_instance-slots.md` |

Reproduce: **path run**. Throwaway `pkg/captcha` test (deleted after the run): `go test ./pkg/captcha -run TestExplore_LogLevelRebuildUsesNewLogger -count=1`. FAIL `reclaimed captcha still enables TRACE after logLevel debug rebuild`. Same sessionKey `captcha:owner:a1486434f5dbbc07` after `cfg.LogLevel` TRACE→DEBUG. Logs: `reclaim_orphan` then `reclaim_reclaim` / waking, same incarnation. Key-equality throwaways passed: captcha `OwnershipKey`, `lapi.OwnershipKey`, and `appsec.Key` are unchanged when only `LogLevel` / `LogFilePath` / `LogFormat` differ.

Outside facts used: in-tree. Reclaim alias remap and Sleep/Wake/Close are dest `vendor/.../reclaim/alias.go` plus `std_go_reclaim.md`. Consumed research index `ext_traefik-middleware-utilities_reclaim_alias/` (no new finding). Active `openspec/changes/`: none.

## Decisions

- Chosen seam: add `LogLevel`, `LogFilePath`, and `LogFormat` to captcha `ownership` so `OwnershipKey` forks on any of those knobs. A log-config-only rebuild Opens a new Client; `newOwnerClient` stores the rebuilt logger. Same pattern as an enterprise-knob change (`TestOwnershipKey_EnterpriseKnobChangeReclaims` / spec scenario Enterprise knob change reclaims).
- Rejected: rebind `Client.log` on reclaim without a key change — Desired forbids it; Out of scope names it.
- Rejected: `LogLevel` only in the key — `plugin.go` freezes all three knobs into one logger; a path or format-only rebuild would keep the same stale `c.log`.
- Rejected: change LAPI or AppSec reclaim keys — Out of scope. They omit log config the same way (measured).
- Rejected: change `pkg/logger` or `plugin.go` `New` logger construction — Out of scope except passing the rebuilt log into a new captcha Open (already the dest path).
- Rejected: a new captcha-reclaim-key spec family — captcha has one Open key; the live SHALL already lives on `core_plugin_middleware_instance-slots`. LAPI’s separate spec exists because of `SessionHex`.
- Blast radius of the key fork (existing table behavior, not a new design): last holder gone → Sleep (captcha Sleep is log-only) → `reclaim_orphan` → grace → Close (`CloseIdleConnections`) → `reclaim_dispose`. `SetAlias` with the same publisher and group remaps `alias:captcha:<name>` to the new incarnation (`alias.go`); watchers receive `Published`. Gate cookies stay valid (gate secret unchanged). Overlap while the old `bindCtx` is still live leaves the old Client Awake until Traefik cancels it; the alias already points at the new Client.
- Live contract: `openspec/specs/core_plugin_middleware_instance-slots/spec.md` (ownership Open key SHALL lists instance-owned captcha knobs; no log knobs today). Propose MODIFIED that list to include `logLevel`, `logFilePath`, `logFormat`. Usage packets named above catch up in devdocs impact. No other live captcha-key SHALL.

## Open questions

- Q: Is including log config in the captcha reclaim key the correct fix, and what is the orphan/dispose/grace/subscriber blast radius?
  Rank: bounded asked — existing `OwnershipKey` contract with 2 production uses, 2 test assertions, 1 live SHALL (roots: `pkg/`, `plugin.go`, `openspec/specs/`, `knowledge/devdocs/`; patterns `captcha.OwnershipKey`, `OwnershipKey(` in `pkg/captcha`, `instance-owned captcha knobs`); Desired “Include the log config in the captcha reclaim key”
  Decision: resolved — yes. Fork the key; do not rebind `c.log`. New Open creates; old incarnation Sleeps, waits process-table grace, then Close. `SetAlias` remaps the captcha instance alias; `Watch` subscribers get the new Client. Same as today’s enterprise-knob reclaim.
  By: explore

- Q: Whether log config is LogLevel only or also LogFilePath and LogFormat.
  Rank: additive asked — adding fields to unexported ownership this change edits; Desired names the log config; Current names all three omitted knobs
  Decision: assumed — hash all three Config fields as stored. plugin.go already uppercases LogLevel before Open and SetAlias. logger.NewWithFormat freezes the three together on Client.log.
  By: explore

- Q: Whether LAPI and AppSec owners keep a stale log level under the same rebuild.
  Rank: additive asked — Unknowns names observe-only; Out of scope “Changing LAPI or AppSec reclaim keys”
  Decision: resolved — yes, same omit. `lapi.OwnershipKey` and `appsec.Key` are unchanged when only the three log knobs differ (throwaway key-equality test). Both constructors store `log` at create. Do not change those keys in this run.
  By: explore

- Q: Who already owns logger construction, captcha Open identity, client address, Host, or trust hop on this path?
  Rank: additive asked — bindIdentity and OwnershipKey already own captcha identity; Desired does not reconstruct request identity
  Decision: resolved — `plugin.go` `New` owns constructing the `*slog.Logger` from the three knobs. `newOwnerClient` / `Client.New` own storing it on the captcha Client. `captcha.OwnershipKey` owns the Open key (`sessionKey`). `bindIdentity` first-wins middleware name and sessionKey and must not grow a logger rewrite. Traefik Yaegi `New(..., name)` owns the middleware string. `pkg/ip.GetRemoteIP` owns client address on ServeHTTP. Do not reconstruct Host, tenant, user, or trust hop. Do not rebind `Client.log` on reclaim.
  By: explore
