# Code review — Spec

- [x] P1 `core_plugin_middleware_bouncer` said `New` "uses the constructor ctx as the AppSec reclaim
  holder". The change binds a derived child instead.
  Status: fixed. Argument: the delta rewords that scenario to "a reclaim context derived from the
  constructor ctx" and adds the rollback requirement, so a strict reader no longer sees a violation.
- [x] P2 `std_go_reclaim_context-lease` requires `Open` to bind a context and to panic on nil.
  Status: pass, unchanged. `bindCtx` is non-nil and is a real context; the leaf does not require the
  caller's own context.
- [x] P3 `core_plugin_appsec_failure-action` already says `captcha` SHALL use the configured captcha
  client. Appsec mode did not.
  Status: fixed. Argument: the delta adds the appsec-mode scenario and the conditional-init rule, and
  the bouncer now honours the requirement that was already on the books.
- [x] P4 `core_plugin_middleware_config-validation` had no rule for appsec-plus-disabled.
  Status: fixed. Argument: added requirement — warn at `WARN`, accept, do not imply AppSec on.
- [x] P5 No spec claims that `New` may write to the caller's `*Config`.
  Status: pass. Argument: the no-mutation requirement is new, not a reversal.
