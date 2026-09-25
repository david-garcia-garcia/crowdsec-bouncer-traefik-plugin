## Context

See proposal.md — Why. Dest `pkg/captcha/session.go` `ownership` hashes middleware name plus instance-owned captcha knobs and omits `LogLevel`, `LogFilePath`, and `LogFormat`. `plugin.go` `New` owns constructing `*slog.Logger` from those three knobs (`logger.NewWithFormat` after uppercasing `LogLevel`) and passes it into `captcha.Open`. `newOwnerClient` / `Client.New` store it on `Client.log`. `bindIdentity` first-wins middleware name and sessionKey only. Identity owner: `plugin.go` `New` constructs the logger; `OwnershipKey` is the Open key. Do not reconstruct that logger in captcha. Do not re-derive client address, Host, or trust hop. Live SHALL: `openspec/specs/core_plugin_middleware_instance-slots/spec.md`.

## Goals / Non-Goals

**Goals:**
- Fork captcha `OwnershipKey` when any of the three log knobs change so create stores the rebuilt logger.
- Keep the existing enterprise-knob reclaim pattern (`TestOwnershipKey_EnterpriseKnobChangeReclaims`).

**Non-Goals:**
- Rebind `Client.log` on reclaim.
- Change LAPI or AppSec reclaim keys.
- Change `pkg/logger` or `plugin.go` `New` logger construction.
- A new captcha-reclaim-key spec family.
- Usage-packet updates (devdocs impact).

## Decisions

1. Hash `cfg.LogLevel`, `cfg.LogFilePath`, and `cfg.LogFormat` as stored on Config. `plugin.go` already uppercases `LogLevel` before Open. Alternative: hash only `LogLevel` — rejected; the three knobs freeze together into one logger, so a path or format-only rebuild would keep a stale `c.log`. Alternative: hash the logger pointer — rejected; the Open key is Config knobs, and the pointer is not stable across rebuilds.
2. Add the three fields on unexported `ownership` as a `Log*` block (`LogFilePath`, `LogFormat`, `LogLevel`, same stem order as Config). Copy them in `ownershipFrom`. Do not restyle the rest of the struct. Alternative: pass a fourth argument into `OwnershipKey` — rejected; every other knob already lives on Config.
3. Leave `bindIdentity` and `Client.New` unchanged. Create on the new key is what installs the new logger. Alternative: rewrite `c.log` on reclaim — rejected; Desired and Out of scope forbid it; explore identity owner forbids a logger rewrite on `bindIdentity`.
4. Tests: add a key-inequality case next to `TestOwnershipKey_EnterpriseKnobChangeReclaims` covering each of the three knobs. Keep `TestOwnershipKey_ExcludesSlotAndBounce`. Do not add LAPI/AppSec key tests in this change.
5. Reclaim blast radius is existing table behavior: last holder Sleeps (captcha Sleep is log-only) → grace → Close; same publisher `SetAlias` remaps `alias:captcha:<name>`; `Watch` gets `Published`. Do not add a new remap path.

## Risks / Trade-offs

- [Orphan of the previous captcha incarnation while Traefik still holds the old bindCtx] → expected overlap; alias already points at the new Client; Close waits process-table grace. Same as an enterprise-knob reclaim.
- [Gate cookies] → gate secret is unchanged, so existing cookies stay valid.
- [LAPI and AppSec keep the same omit] → out of scope; measured; do not silently expand.

## Migration Plan

No operator YAML change. A log-config-only Traefik rebuild starts a new captcha Client instead of Waking the old one. Roll back by reverting the ownership fields; leftover log knobs on Config are unused by the key.

## Open Questions

None — ticket decisions stand on `explore.md`. Propose resolved hashing all three Config fields as stored.
