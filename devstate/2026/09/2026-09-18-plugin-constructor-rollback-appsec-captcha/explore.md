# Explore

## Concepts

- **Reclaim holder** — the utilities table binds one holder per `Open` to the caller's context and drops it
  through `context.AfterFunc` when that context is Done
  (`vendor/github.com/david-garcia-garcia/traefik-middleware-utilities/reclaim/table.go:490-524`). There is no
  explicit `Release`. The only way a constructor can hand a holder back is to cancel the context it bound.
- **What `New` opens, in order** — `lapi.OpenStream` / `lapi.OpenLive` each open two holders (the decision
  store under `StoreKey`, then the client under `SessionKey` / `Key`), and `appsec.Open` opens a third under
  the AppSec listener key. Every one of them binds the context `New` passed down. So one derived context
  cancels all of them, and no per-holder bookkeeping is needed.
- **Two independent configuration axes** — `lapiMode` selects the decision source (`none`/`live` query
  LAPI per request, `stream`/`alone` poll a stream into the cache, `appsec` means no decision source at all).
  `appsecEnabled` toggles the WAF leg, which runs on the pass path in every mode
  (`pkg/bouncer/bouncer.go:341`). `appsec` mode is the only mode that depends on the other knob.
- **Captcha as a failure action** — `bouncerAppsecFailureAction: captcha` is served by `pkg/captcha`, not by
  AppSec JSON `action: captcha` (`core_plugin_appsec_failure-action`). It flows
  `applyAppsecServeHTTP` → `ErrFailureCaptcha` → `handleRemediationServeHTTP`, which needs
  `captchaClient.Valid`.

## Decisions

- Cancel a derived `bindCtx` on the error paths of `New` rather than releasing holders one by one. It covers
  the decision-store holder too, which a per-holder rollback list would have to know about.
- Keep `bindCtx` a child of the constructor ctx (not `context.Background()`), so a Traefik shutdown still
  releases the holder. `std_go_reclaim_context-lease` only requires that `Open` bind *a* context, so the
  derived child satisfies it; `core_plugin_middleware_bouncer`'s wording has to be updated to name it.
- Put the appsec-mode warning in `ValidateParams`, which already takes the logger and is the leaf that owns
  startup validation (`core_plugin_middleware_config-validation`). `New` builds the logger before calling it,
  so the warning lands in whatever sink the operator configured, `logFilePath` included.
- Condition `bouncer.New`'s appsec-mode early return on the effective AppSec failure action rather than
  initialising the captcha client unconditionally. Four lines, and it leaves the no-captcha appsec path
  exactly as fast as it is today.
- Deliverable 5 stays a shallow copy with a comment naming the shared slice and map fields. A deep copy would
  be more code than the defect is worth, and nothing in `New`'s call graph mutates those fields in place.

## Open questions

- Q: Does Yaegi v0.16.1 keep a named return visible to a `defer` closure, so `New`'s rollback fires under
  Traefik?
  Decision: resolved — `yaegi test -v .` at v0.16.1 runs the root suite, including the rollback test, with
  the named-`err` defer in place. Kept the named return as the ticket asked.
  By: implement
- Q: Is the `e2e (docker + pester)` CI job green on this head, given it cannot run locally (hard-coded ports
  8000/8080/8081 and subnet `172.20.0.0/16` collide with the owner's dev stack)?
  Decision: assumed — rely on CI on the pushed head and compare the previous head's conclusions at
  `api.github.com/repos/<owner>/<repo>/commits/<sha>/check-runs` before treating a red result as ours.
  By: implement
- Q: Should the appsec-plus-disabled combination be rejected instead of warned?
  Decision: resolved — owner decided warn-and-start. Rejecting is out; implying `appsecEnabled` on is
  out too, because `AppsecHost` defaults to `crowdsec:7422` and `BouncerAppsecFailureAction`
  defaults to `ban`, so implying would turn a do-nothing config into a ban-everything one on upgrade.
  By: explore
