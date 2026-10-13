## Context

See `proposal.md` Why. `pkg/reclaim` is a shim over utilities `reclaim`; that table drops a holder only from
`context.AfterFunc(ctx, …)` when the bound context is Done (`vendor/…/reclaim/table.go:490-524`). There is no
`Release`. `New` makes up to three `Open` calls (decision store, LAPI client, AppSec client) and passes the
same context to all of them.

FindSpecHost:

```
verdicts:
  - { deltaId: constructor-rollback,   fold|new: fold, spec-id: core_plugin_middleware_bouncer,          confidence: high, candidates: [core_plugin_middleware_bouncer, std_go_reclaim_context-lease, core_plugin_lapi_reclaim-key] }
  - { deltaId: config-snapshot,        fold|new: fold, spec-id: core_plugin_middleware_bouncer,          confidence: high, candidates: [core_plugin_middleware_bouncer, core_plugin_middleware_config-validation] }
  - { deltaId: appsec-mode-warning,    fold|new: fold, spec-id: core_plugin_middleware_config-validation, confidence: high, candidates: [core_plugin_middleware_config-validation, core_plugin_middleware_bouncer] }
  - { deltaId: appsec-mode-captcha,    fold|new: fold, spec-id: core_plugin_appsec_failure-action,        confidence: high, candidates: [core_plugin_appsec_failure-action, core_plugin_middleware_captcha-routing, core_plugin_middleware_bouncer] }
```

`core_plugin_middleware_bouncer` already owns `New`'s contract, including the sentence that names the
constructor ctx as the AppSec reclaim holder, so both constructor deltas fold there rather than onto
`std_go_reclaim_context-lease` (which governs the table, not its callers) or `core_plugin_lapi_reclaim-key`
(which governs key composition). The warning folds onto the startup-validation leaf. Captcha-as-AppSec-failure
is already a requirement on `core_plugin_appsec_failure-action`; appsec mode is a hole in it, not a new
capability, and `core_plugin_middleware_captcha-routing` governs request routing once the client is valid.

## Goals / Non-Goals

**Goals:**

- A failed `New` leaves no reclaim holder and no running ticker.
- Cancelling Traefik's constructor context still releases the holders a successful `New` opened.
- An operator who writes `crowdsecMode: appsec` without `crowdsecAppsecEnabled` sees a warning naming the
  consequence.
- `crowdsecAppsecFailureAction: captcha` serves the challenge in appsec mode.
- `New` does not write to the caller's `*Config`.

**Non-Goals:**

- Rejecting the appsec-plus-disabled config, or implying `crowdsecAppsecEnabled` on.
- A deep copy of `Config`'s slice and map fields.
- #33's error plumbing for `ip.NewChecker` / `GetTemplate`, or its `servehttp_test.go`.
- Any change to the reclaim table itself, or a `Release` API.
- Changing which keys the holders are opened under.

## Decisions

1. **One derived context, cancelled on error.** `bindCtx, releaseHolders := context.WithCancel(ctx)` plus
   `defer func() { if err != nil { releaseHolders() } }()` with a named `err` return. Alternative: track each
   opened holder and cancel a per-holder context — rejected, it duplicates what the table already does with
   `AfterFunc` and would have to know that `OpenStream` opens the decision store too. Alternative: a
   closure-captured `ok` bool — rejected by the ticket.
2. **`bindCtx` is a child of the constructor ctx, not `Background`.** A root context would keep the holder
   alive across a Traefik shutdown. `std_go_reclaim_context-lease` only requires that `Open` bind *a* context.
   `core_plugin_middleware_bouncer` is updated so its wording names the derived context.
3. **Success path never cancels.** `releaseHolders` runs only when `err != nil`. The `context.WithCancel`
   child is released with its parent, so `go vet`'s `lostcancel` is satisfied by the deferred call.
4. **Warning lives in `ValidateParams`.** It already takes the logger, it is the leaf that owns startup
   validation, and `New` builds the logger before calling it, so the warning reaches `logFilePath` too. It is
   `log.Warn`, above the default `INFO` threshold, and names both the combination and the consequence.
5. **`bouncer.New` conditions its appsec-mode early return on the effective failure action.** Initialising
   the captcha client unconditionally would also pay for it on the appsec-mode paths that can never serve a
   challenge. `EffectiveFailureAction` is already computed on the handler, so the condition reads off that.
6. **Deliverable 5 stays a shallow copy with a comment.** `Config`'s `[]string` and `map[string]string` fields
   still alias the caller's; nothing in `New`'s call graph mutates them in place, and the comment says so at
   the copy site so the next in-place mutation is not written on a false assumption. A deep copy is more code
   than a behaviour-neutral fix should carry.

## Risks / Trade-offs

- [Yaegi v0.16.1 and a named return read by a `defer`] → the known risk in this change: #31's `37e1914` broke
  the docker e2e on exactly that construct and `2535b19` fixed it. Gate is `yaegi test -v .` at the pinned
  version plus `go test . -count=1`, not just `./pkg/...`.
- [A `context.WithCancel` child per middleware on the success path] → one extra child context per `New`,
  released when Traefik's context is. Cheaper than the leaked ticker it replaces.
- [Warning instead of rejection leaves a do-nothing middleware running] → owner's decision. Rejecting would
  refuse to boot over a config that only fails to enforce; implying AppSec on would point at
  `crowdsec:7422` by default and, with the default `ban` failure action, ban every request on that router.
- [Snapshotting `*config` hides a mutation some caller may rely on] → every mutation in the call graph is
  idempotent and the reclaim identity keys are computed after `Prepare` either way, which is why #22 was
  closed as behaviour-neutral. Proven by test: the caller's struct is unchanged after `New`.

## Migration Plan

No operator JSON/YAML key change, no new config field. Rollback is revert.
