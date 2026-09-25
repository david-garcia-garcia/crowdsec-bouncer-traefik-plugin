# Requirement
IssueKey: 2026-09-25-log-config-reclaim-key

## Problem
A middleware that owns captcha is rebuilt after `logLevel` changes from `trace` to `debug`. The reclaimed captcha instance keeps the old `trace` level.

## Current (code)
- `pkg/captcha/session.go` `ownership` / `OwnershipKey` hashes middleware name plus captcha owner knobs. `LogLevel`, `LogFilePath`, and `LogFormat` are not on that payload, so a log-config-only rebuild hashes the same Open key.
- `pkg/captcha/session.go` `Open` reclaims by that key; `newOwnerClient` runs only on create and stores the constructor `log` on the Client.
- `pkg/captcha/captcha.go` `Client.New` sets `c.log` at create; `bindIdentity` does not replace the logger on reclaim.
- `plugin.go` `New` builds `log` from `config.LogLevel` / `LogFilePath` / `LogFormat` and passes it into `captcha.Open`. Reclaim still returns the prior Client.

## Desired
- After that rebuild, the owned captcha instance uses the new log config, not the old `trace` level.
- Include the log config in the captcha reclaim key (the believed fix). Do not substitute a different design (for example rebinding the logger on the same key).

## Affected
- `pkg/captcha/session.go` — `ownership` / `OwnershipKey` / `Open`
- `pkg/captcha/zzz_owner_test.go` — owner-key coverage

## Out of scope
- Changing LAPI or AppSec reclaim keys, even though they omit log config the same way (`pkg/lapi/identity.go` `ownership`, `pkg/appsec/session.go` `identity`).
- Rebinding `Client.log` on reclaim without a key change.
- Changing logger construction in `pkg/logger` or `plugin.go` `New` except as needed to pass the rebuilt log into a new captcha Open.

## Unknowns
- Whether the believed fix is correct, and its blast radius (orphan/dispose of the old captcha incarnation, grace, subscribers on the instance alias). Explore owns that.
- Whether "log config" is `LogLevel` only or also `LogFilePath` and `LogFormat` (`pkg/configuration/configuration.go`). The ticket example is level; the phrase is log config.
- Whether LAPI and AppSec owners keep a stale log level under the same rebuild (same key shape). Observe only; not this change.

## Tensions
None. The ticket names the captcha owner path and the reclaim-key fix; dest code omits log config from that key and freezes `c.log` at create.
