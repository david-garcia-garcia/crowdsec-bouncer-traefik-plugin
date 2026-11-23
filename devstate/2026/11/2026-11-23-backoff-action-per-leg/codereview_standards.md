# Standards

1. [judgement] Duplicated Code — `pkg/bouncer/bouncer_serve_lapi.go:99` — `applyLapiFailureAction` and the new `applyBackOffAction` (`pkg/bouncer/bouncer_backoff_action.go:19`) carry the same passthrough / captcha / ban switch; only the action field and the captcha downgrade reason differ
   Fix: Let `applyLapiFailureAction` call one shared per-leg action writer with `b.lapiFailureAction`
   Status: skipped
   Argument: judgement; the two differ in the captcha downgrade reason (LAPI failure keeps `ReasonLAPI` for stream-unhealthy too) and folding them reshapes the per-leg failure-action family, which belongs to the common-leg-abstraction debt, not this change.
2. [judgement] Duplicated Code — `pkg/configuration/configuration.go:255` — six `Effective*Action` resolvers with identical bodies that differ only in the empty-value default
   Fix: One resolver taking the leg default, wrapped by the named per-leg functions
   Status: skipped
   Argument: judgement; the owner chose a static, named default per leg and action, and each resolver states that default in its own name and comment; a shared helper would save four lines and hide the default from the call site.
