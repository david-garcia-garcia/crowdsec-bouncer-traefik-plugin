# Spec

1. [wrong] Empty rateLimitFailureAction serves ban — `pkg/bouncer/bouncer.go:143` — config-validation delta says `ValidateParams` SHALL fail when `rateLimitFailureAction` is not `passthrough`, `ban`, or `captcha` (default `passthrough`), but `validateFailureAction` (`pkg/configuration/configuration.go:498`) accepts `""` and `EffectiveFailureAction("")` maps it to `ban`, so an explicit empty value fails closed instead of taking the passthrough default
   Fix: Map an empty value to passthrough for this leg (as `EffectiveModsecFailureAction` does) or reject `""` in `validateRateLimit`
   Status: done
   Argument: New `configuration.EffectiveRateLimitFailureAction` maps empty to passthrough, used at `bouncer.go:143`; regression case "empty is passthrough" in `TestRateLimit_failureActions`.
2. [wrong] Redis failures can log WARN/ERROR per request — `pkg/ratelimit/client.go:108` — `core_plugin_ratelimit_client` says the plugin MUST NOT log WARN or ERROR per failing request, but the plugin logger is handed to `simpleredis`, which logs ERROR `do: NOAUTH` (`vendor/.../simpleredis/resp.go:84`) and WARN `dial: NOAUTH` (`pool.go:282`) on every dial with a wrong password, and WARN on an EOF read (`resp.go:75`), so exact mode with a bad password writes ERROR+WARN on each request
   Fix: Give `simpleredis.Config.Logger` a handler that caps library lines at DEBUG (or narrow the requirement to the plugin's own lines)
   Status: done
   Argument: `newClient` hands simpleredis `debugCappedLogger(log)` (`pkg/ratelimit/library_log.go`), which writes every library record at DEBUG; `TestClient_wrongPasswordLogsAtDebugOnly` (fake Redis answering WRONGPASS) asserts no WARN/ERROR and the NOAUTH line at DEBUG, and fails without the cap.
