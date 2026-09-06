# Explore
IssueKey: 2026-09-06-plugin-constructor-rollback

## Concepts

- `plugin.go` `New` passes Traefik's constructor `ctx` into `lapi.OpenStream` / `lapi.OpenLive` and `appsec.Open`. Each `reclaim.OpenWithGrace` starts `watch(key, id, e, ctx)`; the holder drops only when that `ctx` ends (`pkg/reclaim/table.go:269-273`).
- On constructor error after a successful open, Traefik's `ctx` may remain live (tests use `context.Background()`), so stream/metrics tickers keep running until an external cancel.
- Reclaim has no public `Drop` API; holder release is driven by context cancellation. A child `context.WithCancel(parent)` bound at open time inherits parent lifetime on success and can be cancelled immediately on failure.
- `crowdsecMode: appsec` with `CrowdsecAppsecEnabled: false` skips LAPI and AppSec opens but still returns a bouncer that forwards all non-trusted traffic (`plugin.go:59-77`, `pkg/bouncer/bouncer.go:156-158`, `294-298`).
- Existing tests cover reclaim sharing/grace/dispose on successful `New` only (`plugin_test.go`); no mode-branch or error-rollback coverage.

## Decisions

- **Rollback mechanism:** wrap backend opens in `bindCtx, cancelBind := context.WithCancel(ctx)`. Pass `bindCtx` to all `lapi.Open*` / `appsec.Open` calls. On any error return from `New`, call `cancelBind()` before returning so reclaim drops holders immediately. On success, leave `bindCtx` live (child of Traefik `ctx`) — no double-open or reclaim API change.
- **Appsec pass-through:** after `ValidateParams`, reject `CrowdsecMode == AppsecMode && !CrowdsecAppsecEnabled` in `plugin.go` with a clear error. Do not change `pkg/configuration/configuration.go` in this ticket.
- **Tests:** use `reclaim.ResetForTestWith(0)`, httptest LAPI/AppSec stubs, and `reclaim.Peek(lapi.SessionKey(cfg))` / `reclaim.Peek(appsec.Key(cfg))` to assert holder counts. Cover alone (stream session), appsec-only enabled, live+AppSec (distinct keys), appsec-mode disabled rejection, and LAPI-open-then-AppSec-fail rollback.
- **Scope:** touch only `plugin.go` and `plugin_test.go`; no captcha, bouncer ServeHTTP, or configuration validation matrix changes.

## Open questions

- Q: Whether appsec-mode rejection belongs solely in `plugin.go` or also needs `ValidateParams` in `configuration.go`?
  Decision: assumed — guard in `plugin.go` after `ValidateParams`; a future configuration ticket may centralize the rule.
  By: explore

- Q: Whether `bouncer.New` failure after both backends open requires rolling back both LAPI and AppSec holders?
  Decision: assumed — yes; one shared `bindCtx` for all opens means `cancelBind()` on any downstream error drops every holder opened in that constructor call.
  By: explore
