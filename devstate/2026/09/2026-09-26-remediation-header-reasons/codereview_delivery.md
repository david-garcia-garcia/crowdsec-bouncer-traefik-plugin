# Delivery

## Motivation

`bouncerRemediationHeadersCustomName` is an optional response header so Traefik JSON access logs (`downstream_<Name>`) can tell a plugin bounce from an origin 403. Drop origin is already known internally for usage-metrics (`MetricsOrigin`, `OriginPlugin*`). The header stays off when the name is empty.

When the name is set, the value is only a kind token: `ban`, `captcha`, `solved-captcha`, `error:client-disconnected`, or a raw AppSec `action`. Every ban page writes `ban` whether the cause was a CrowdSec decision, fail-closed LAPI or cache, AppSec `action: ban`, an empty-body AppSec challenge that fell through to the ban page, an unparseable client IP, or a captcha kind on a router that cannot serve a challenge. Challenge pages write `captcha`; a successful solve writes `solved-captcha`; AppSec envelope relay copies the action as-is. LAPI origin (`crowdsec`, `lists:firehol_level1`, empty intern overflow) never appears on the header.

Operators who panel on those Traefik fields cannot tell a CrowdSec decision from fail-closed or AppSec, and cannot split list vs crowdsec origin without leaving the access log. The only access-log signal stays “plugin handled it,” not why.

Priority: P2 — real operator pain, with a workaround or limited blast radius

## Implementation

An unexported formatter in `pkg/bouncer` joins `kind:reason`, or `kind:reason:origin` when reason is `lapi` and origin is non-empty. Ban, AppSec, disconnect, and captcha-downgrade writers pass an explicit closed reason token; plugin origins stay a reason, never a third field. LAPI third field is header-safe `MetricsOrigin` (strip CR/LF/TAB; prefix `lists:` becomes `lists_` only). Captcha stays a setter: `ServeHTTP` takes the already-formatted challenge value plus the header name; Pass 302 and `WriteSolvedRedirect` write `captcha:solved`. Unknown AppSec actions become `{sanitized-action}:appsec`. Same config key; empty still disables.

## What this changes
**Operators.** When `bouncerRemediationHeadersCustomName` is set, Traefik `downstream_<Name>` values become `kind:reason` or `kind:reason:origin`, so queries matching `ban`, `captcha`, `solved-captcha`, or a raw AppSec action must change (`error:client-disconnected` unchanged; no new key; empty still disables).
**Admin users.** None.
**Developers.** `captcha.Client.ServeHTTP` takes a fifth argument (already-formatted challenge-page header value); header consumers split at most three `:` fields on the closed vocabulary.
**End users.** None.
