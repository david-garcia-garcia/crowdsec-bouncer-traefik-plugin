## Context

See proposal.md — Why. Yaegi keeps the CreateConfig pointer and passes it to `New` (`knowledge/research/ext_traefik_plugins_yaegi-constructor/notes.md`). Today `plugin.go` writes LogLevel and path aliases on that pointer, then `Prepare` inlines secrets and rewrites CAPI routing on the same struct. `IdentityHex` hashes the result. Explore: copy-then-mutate; no Prepared type.

## Goals / Non-Goals

**Goals:**
- One snapshot pointer for Prepare, Key, connection `New`, and `bouncer.New`.
- Traefik’s Config pointer unchanged after `New`.
- Same CAPI rewrite and `GetVariable` secret loading as today, on the snapshot.

**Non-Goals:**
- A new Prepared type or file-split of `configuration.go`.
- Moving `GetTLSConfigCrowdsec`.
- Changing DecisionScopeHeaders identity.
- Folding captcha `GetVariable` from `bouncer.New` into `Prepare`.
- Deep-cloning slice/map fields.

## Decisions

1. **Shallow copy in `plugin.go` `New`.** `prepared := *config` then all later calls take `&prepared`. Alternative: `Prepare` returns a copy — rejected; plugin.go still writes Traefik’s pointer for LogLevel/aliases unless those move too. Alternative: new Prepared type — rejected; not smaller.

2. **`Prepare` signature stays `Prepare(cfg *Config, log) error`.** It keeps mutating `cfg`. The constructor passes the snapshot. Alternative: return `*Config` — extra API with no second caller today.

3. **Logger ToUpper without writing Traefik.** `logger.NewWithFormat(strings.ToUpper(config.LogLevel), …)` then assign ToUpper and aliases on `prepared`. Alternative: mutate `config.LogLevel` first — rejected; that is the bug.

4. **Captcha key inlining stays in `bouncer.New`.** Those writes run on the snapshot. Alternative: move into Prepare — out of bound.

5. **Shallow copy of slices/maps.** This ticket does not write `DecisionScopeHeaders` or trusted-IP slices. Alternative: deep clone — extra code, sibling identity ticket.

## Risks / Trade-offs

- [Shared slice/map backing] → Do not append to those fields on the snapshot. Sibling tickets own map identity.
- [Tests asserting post-New mutation] → Switch them to the snapshot or assert the caller pointer is unchanged.
- [Yaegi] → Keep `CreateConfig`/`New` on the module root; no new constructor type.

## Migration Plan

None. Internal constructor locality only. Rollback is the previous tag. No YAML key change.
