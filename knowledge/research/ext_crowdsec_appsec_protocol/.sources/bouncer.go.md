---
url: https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/blob/04d928872df12bdb9d953b2d92948e0b89692d6a/bouncer.go
title: bouncer.go appsecQuery
fetched: 2026-09-05
authority: source
ref: github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin@04d928872df12bdb9d953b2d92948e0b89692d6a:bouncer.go
---

crowdsecAppsecHeader = "X-Crowdsec-Appsec-Api-Key" (not X-Api-Key). Also sets X-Crowdsec-Appsec-Ip, -Verb, -Host, -Uri, -User-Agent. Does not set X-Crowdsec-Appsec-Http-Version.

appsecQuery: POST when a body is buffered; GET when no body or when the body is treated unreadable.

On httpClient.Do error or status 502/503/504: log appsecQuery:unreachable. If appsecUnreachableBlock, return error (caller bans). Else return nil (allow).

On status 500: log appsecQuery:failure. If appsecFailureBlock, return error "appsecQuery statusCode:500". Else return nil (allow).

On any other non-200 (including 401 and 403): return error "appsecQuery statusCode:%d" with no JSON body parse. Caller handleNextServeHTTP bans with ReasonAPPSEC.
