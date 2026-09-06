# AppSec unreadable body

How CrowdSec reference bouncers treat HTTP/2+ request bodies that cannot be buffered (no `Content-Length`, typical of bidirectional gRPC streams).

Fetched: 2026-09-06. Lua pin: `github.com/crowdsecurity/lua-cs-bouncer@59f3521e3918377fc1eb97d59a4056b6e9f5782f`. Traefik pin: `github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin@04d928872df12bdb9d953b2d92948e0b89692d6a`.

## Option name and defaults

| Bouncer | Config key | Default | `false` | `true` |
|---|---|---|---|---|
| nginx (lua-cs-bouncer) | `APPSEC_DROP_UNREADABLE_BODY` | `false` | Forward to AppSec **headers only** (GET to AppSec; client body streams through untouched). | Block at the bouncer (403, `FALLBACK_REMEDIATION`); AppSec is not called. |
| Traefik plugin | `crowdsecAppsecUnreadableBodyBlock` | `true` in `configuration.New()` | Same headers-only AppSec check as lua default. | Drop POST/PUT/PATCH with unreadable body before AppSec. |

Official nginx docs name the option and default: [nginx bouncer](https://docs.crowdsec.net/u/bouncers/nginx) (`APPSEC_DROP_UNREADABLE_BODY=false #default`). Extract: `.sources/nginx-bouncer-docs.md`.

There is no `CrowdsecAppsecDropUnreadableBody` key on Traefik master at this commit; the mirror is `CrowdsecAppsecUnreadableBodyBlock`. README config reference lists default `true` and matches source; the long example YAML sets `crowdsecAppsecUnreadableBodyBlock: false` as an operator choice to align with lua default. ([README](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/blob/04d928872df12bdb9d953b2d92948e0b89692d6a/README.md), extract `.sources/traefik-readme.md`; [configuration.go](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/blob/04d928872df12bdb9d953b2d92948e0b89692d6a/pkg/configuration/configuration.go), extract `.sources/traefik-configuration.go.md`)

## When a body is "unreadable"

Both bouncers refuse to buffer the body when the request is HTTP/2 or HTTP/3 **and** has no `Content-Length`.

**Lua:** `get_body()` returns `unreadable_body=true` when `ngx.req.http_version() >= 2` and `ngx.var.http_content_length == nil` for methods that may carry a body (`POST`, `PUT`, `PATCH`). It does not call `ngx.req.read_body()` in that case because the lua API errors without `Content-Length`. ([crowdsec.lua](https://github.com/crowdsecurity/lua-cs-bouncer/blob/59f3521e3918377fc1eb97d59a4056b6e9f5782f/lib/crowdsec.lua), extract `.sources/lua-crowdsec-get-body.md`)

**Traefik:** `isBodyUnreadable` is true when `ProtoMajor >= 2` and `ContentLength < 0`. ([bouncer.go](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/blob/04d928872df12bdb9d953b2d92948e0b89692d6a/bouncer.go), extract `.sources/traefik-bouncer-isBodyUnreadable.md`)

Official docs state the same trigger: HTTP2/HTTP3 without Content-Length; default leaves body unanalyzed; set `APPSEC_DROP_UNREADABLE_BODY=true` to drop. ([nginx bouncer](https://docs.crowdsec.net/u/bouncers/nginx))

## Drop vs headers-only path

**Lua `APPSEC_DROP_UNREADABLE_BODY=true`:** `AppSecCheck` returns ban remediation and HTTP 403 before calling AppSec when `unreadable_body` and the flag is set. ([crowdsec.lua](https://github.com/crowdsecurity/lua-cs-bouncer/blob/59f3521e3918377fc1eb97d59a4056b6e9f5782f/lib/crowdsec.lua), extract `.sources/lua-crowdsec-appseccheck-drop.md`)

**Lua default (`false`):** AppSec receives a GET with CrowdSec headers only (`body_len == 0`); original stream body is not sent to AppSec. Test: `t/20_appsec_keep_unreadable_body.t`. ([tests](https://github.com/crowdsecurity/lua-cs-bouncer/blob/59f3521e3918377fc1eb97d59a4056b6e9f5782f/t/20_appsec_keep_unreadable_body.t), extract `.sources/lua-test-keep-unreadable-body.md`)

**Traefik `CrowdsecAppsecUnreadableBodyBlock=true` (default):** `appsecQuery` returns error `appsecQuery:unreadableBody dropped` for POST/PUT/PATCH; GET/HEAD still proceed headers-only. ([bouncer.go](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/blob/04d928872df12bdb9d953b2d92948e0b89692d6a/bouncer.go), extract `.sources/traefik-bouncer-appsecQuery.md`)

**Traefik `false`:** builds GET to AppSec with nil body, mirroring lua headers-only path. ([README](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/blob/04d928872df12bdb9d953b2d92948e0b89692d6a/README.md))

## GET exemption

With drop enabled, GET requests on HTTP/2+ without `Content-Length` are **not** dropped — no body is expected. Lua test `t/19_appsec_drop_unreadable_body_get.t`; Traefik `isMethodWithBody` excludes GET. ([lua test](https://github.com/crowdsecurity/lua-cs-bouncer/blob/59f3521e3918377fc1eb97d59a4056b6e9f5782f/t/19_appsec_drop_unreadable_body_get.t), extract `.sources/lua-test-drop-get.md`)

## Security note (official)

Docs warn that default `false` means WAF may not analyze the body and recommend `true` to avoid bypass on gRPC-style streams. ([nginx bouncer](https://docs.crowdsec.net/u/bouncers/nginx), extract `.sources/nginx-bouncer-docs.md`)
