# Nested sloggers

## Language

**Nested component logger**:
A `slog.Logger` child created with `log.With` on the Bouncer, LAPI Client, AppSec Client, or Captcha Client so every line from that unit carries its identity.
_Avoid_: a helper around `With`; repeating `traefikName` / `instanceName` / `leg` / `sessionKey` on every call site

## Overview

Four constructors nest. `bouncer.New` sets `traefikName`. `lapi.New`, `appsec.New`, and `captcha.Open` set `traefikName`, `instanceName`, `leg`, and `sessionKey`. Stream ticks and `reportMetrics` inherit those fields.

## How to use

- Call `log.With(...)` once in the constructor and store the child on the struct.
- Log the event (`startup`, `new`, `items`). Do not pass identity fields again on that line.
- Keep request-path Trace on the bouncer logger (`std_go_logger_debug-attrs`).

## Pattern snippet

```go
log = log.With("traefikName", name)
log = log.With("traefikName", middlewareName, "instanceName", cfg.CrowdsecLapiInstanceName, "leg", instance.LegLAPI, "sessionKey", bindKey)
log.Debug("handleStreamTicker:poll", "startup", startup, "interval", interval)
```

## Key files

- `pkg/bouncer/bouncer.go` — bouncer nest
- `pkg/lapi/client.go` — LAPI nest
- `pkg/appsec/client.go` — AppSec nest
- `pkg/captcha/session.go` — captcha nest

## Gotchas

- `slog.With` appends. Do not nest the same key twice on one logger.
- Client literals in tests do not go through `New`. Call `log.With` in the helper before asserting identity fields.
