# Explore

## Concepts
**GetRemoteIP** already owns the client address. The new flag is a second path inside that owner, not a second owner. Traefik's entrypoint `XForwarded` handler is the owner of whether `X-Real-Ip` is spoofable; this plugin must not re-derive that.

**BouncerForwardedTrustedIPs** stays the hop checker. The flag means "do not consult the checker", implemented as an argument on `GetRemoteIP`, not a field on `PoolStrategy`.

**Effective header** is a constructor concern on `bouncer.New` (`forwardedCustomHeader`). `pkg/ip` keeps reading whatever name it is given.

## Decisions
Ticket decisions 1–6 stand. Do not reopen them.

- Field `BouncerForwardedInsecure` sits immediately after `BouncerForwardedHeader` (still between that field and `BouncerForwardedTrustedIPs` even though `LapiScopeHeaders` is also in that span).
- Startup log text when the flag is on: `BouncerForwardedInsecure enabled, using header <name>`.
- Dest lacks the cited Gotcha lines; write the post-flag wording onto master's `core_plugin_ip.md`.
- Research notes file is not on dest and is outside the scope fence; do not add or edit it.

## Open questions
- Q: Who already owns the client address this change would set?
  Decision: resolved — `pkg/ip.GetRemoteIP` is the owner. Traefik's entrypoint owns sanitizing `X-Real-Ip` before the plugin runs. Reuse those outputs; do not parse `RemoteAddr` again in a neighbor.
  By: explore

- Q: What is the exact Info log sentence?
  Decision: resolved — `BouncerForwardedInsecure enabled, using header ` plus the effective name. Emitted only when the flag is on, once at `bouncer.New`.
  By: explore

- Q: Should this run add `knowledge/research/ext_traefik_forwardedheaders_x-real-ip/` which is untracked in the caller tree and absent on dest?
  Decision: resolved — no. Outside the scope fence; dest does not have the file.
  By: explore
