# Code review — Performance

- [x] F1 One extra `context.WithCancel` child per `New`, alive for the middleware's lifetime.
  Status: accepted. Argument: one cancel registration on Traefik's context per router, released with
  that context. It replaces a leaked stream ticker that polled LAPI forever, so the trade is not
  close.
- [x] F2 `prepared := *config` copies the whole `Config` struct once per `New`.
  Status: accepted. One struct copy at construction, not on the request path.
- [x] F3 Captcha client initialisation in appsec mode.
  Status: pass. Argument: conditional on the effective failure action being `captcha`, so appsec-mode
  routers with `ban` or `passthrough` keep today's early return and pay nothing.
- [x] F4 Request path untouched.
  Status: pass. Argument: no change under `ServeHTTP`; the diff is `New`, `bouncer.New`, and
  `ValidateParams`, all startup-only.
