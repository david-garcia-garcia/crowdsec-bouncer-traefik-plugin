# Explore
IssueKey: 2026-09-05-config-prepare-snapshot

## Concepts

Traefik Yaegi stores the `CreateConfig` pointer and passes that same `*configuration.Config` into every `New` (`knowledge/research/ext_traefik_plugins_yaegi-constructor/notes.md`). Today `plugin.go` and `Prepare` write through that pointer (LogLevel, path aliases, CAPI rewrite, secret file inlining). `IdentityHex` then hashes whatever is left. Reclaim identity is therefore a hash of a mutated DTO, and the host’s live Config is a scratchpad.

A **snapshot** is a `configuration.Config` value that is not Traefik’s pointer. Prepare, Key, `crowdsecconnection.New`, and `bouncer.New` share that one value. Traefik’s original pointer is left as decoded.

```
Traefik Config pointer ──copy──► snapshot
                                 │ ToUpper LogLevel, path aliases
                                 │ ValidateParams
                                 │ Prepare (CAPI / secrets)
                                 ▼
                    Key / IdentityHex / connection.New / bouncer.New
```

`core_plugin_middleware.md` already says Prepare then `Key(config)` then `bouncer.New`. After this change the `config` in that snippet is the snapshot, not Traefik’s pointer.

Reclaim still keys on `IdentityHex` of connection fields. Client address stays `pkg/ip.GetRemoteIP`. DecisionScopeHeaders identity is a sibling; do not add it here.

## Decisions

- Copy-then-mutate of `configuration.Config`. No new Prepared type: it would duplicate the DTO, force a file split, and is not smaller.
- Copy in `plugin.go` `New` before any write: `prepared := *config` then use `&prepared`. `Prepare` keeps mutating its argument (the snapshot). Traefik’s pointer is never assigned.
- Shallow struct copy is enough. Prepare and plugin.go only assign scalars; they do not append to slices or mutate `DecisionScopeHeaders` in place. Sharing slice/map backing with Traefik is acceptable for this ticket.
- Path aliases and LogLevel ToUpper run on the snapshot only. Logger can `ToUpper` for construction without writing Traefik’s field.
- `bouncer.New` captcha `GetVariable` writes stay where they are; they run on the snapshot pointer, so they no longer touch Traefik.
- Identity hashes the snapshot after Prepare (same field set as today). Do not hash the unprepared Traefik DTO.
- Tests that need prepared secrets/CAPI host use the snapshot (`Prepare` on a copy, or inspect via Key). Tests that pass `New` a pointer SHOULD see that pointer unchanged.

## Open questions

- Q: copy-then-mutate vs a new Prepared type?
  Decision: resolved — copy-then-mutate of `configuration.Config`. Prepared type is not smaller (duplicate DTO, likely a new file, all Key/New/Bouncer signatures).
  By: explore

- Q: Where does the copy live — Prepare return vs plugin.go before mutate?
  Decision: assumed — copy at the start of `plugin.go` `New` (`prepared := *config`), then existing Prepare/Key/New/Bouncer calls take `&prepared`. Prepare signature stays `Prepare(cfg *Config, log) error` mutating cfg. Moving copy into Prepare would still leave plugin.go alias/ToUpper writes on Traefik’s pointer unless those move too; one copy at the constructor is smaller.
  By: explore

- Q: Shallow vs deep copy of slice/map fields?
  Decision: assumed — shallow (`*cfg`). This ticket does not write those fields; DecisionScopeHeaders identity is a sibling.
  By: explore

- Q: Do captcha key writes in `bouncer.New` move into Prepare?
  Decision: assumed — no. Pass the snapshot into `bouncer.New`; those writes stay on the snapshot. Bound the ask: do not fold captcha loading into Prepare.
  By: explore

- Q: Who owns reclaim identity (connection hash) vs Traefik’s Config DTO vs client address?
  Decision: resolved — `IdentityHex` on the prepared snapshot owns the reclaim key. Traefik/Yaegi owns the CreateConfig pointer (do not mutate it). Client address stays `pkg/ip.GetRemoteIP`. Do not put DecisionScopeHeaders in identity (sibling).
  By: explore
