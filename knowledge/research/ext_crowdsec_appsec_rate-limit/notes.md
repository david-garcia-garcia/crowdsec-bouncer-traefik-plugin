# AppSec RateLimit helper

What the CrowdSec AppSec `RateLimit()` hook helper does, which release ships it, what the bouncer receives, and whether it creates LAPI decisions.

Fetched: 2026-11-14. Source pin: `github.com/crowdsecurity/crowdsec@3d369d64eb3e9ba770ed39aedc83ffd3170aef4c` (tag `v1.8.2`). Docs pin: `github.com/crowdsecurity/crowdsec-docs@84602c95254a6734a3bad8b0939981fd34e84320`. Hub pin: `github.com/crowdsecurity/hub@45ddd98db0db97d9da2b21d2bcf007b5cecd3c3f`.

## Release that ships it

- **First stable release: `v1.8.2`** (published 2026-10-26). Release notes: "Brings rate limiting feature … to the WAF" and "[WAF] Add RateLimiting feature (#4721)". ([v1.8.2 release](https://github.com/crowdsecurity/crowdsec/releases/tag/v1.8.2), extract `.sources/v1.8.2-release.md`)
- **Not in `v1.8.0` or `v1.8.1`.** `pkg/appsec/ratelimit.go` returns 404 at `v1.8.0-rc1`, `v1.8.0-rc2`, `v1.8.0`, `v1.8.1`, `v1.8.2-rc1` and every checked `v1.7.x`. It is present at `v1.8.2-rc2`, `v1.8.2` and `master`. ([raw tag check](https://raw.githubusercontent.com/crowdsecurity/crowdsec/v1.8.0/pkg/appsec/ratelimit.go), extract `.sources/v1.8.2-release.md`)
- Added by PR [#4721](https://github.com/crowdsecurity/crowdsec/pull/4721) "waf: add RateLimit() helper", merged 2026-10-20 (`ab20e2c2`). No `v1.9.x` tag exists on 2026-11-14.
- Docker Hub: newest release image tag is **`crowdsecurity/crowdsec:v1.8.2`** (also `-slim`, `-debian`; `latest` points at the same push, 2026-10-29). Only `dev` / `dev-debian` are newer, and they are unreleased builds. ([Docker Hub tags](https://hub.docker.com/r/crowdsecurity/crowdsec/tags), extract `.sources/dockerhub-tags.md`)

## Syntax and where it may be used

Official docs ([rate limiting](https://docs.crowdsec.net/docs/appsec/rate_limiting), extract `.sources/rate_limiting.md`):

- Call form: `RateLimit("<key>", "<count>/<s|m|h>")` or `RateLimit("<key>", "<count>/<unit>", <source expr>)`. Returns `bool` (`true` = over the limit, already blocked).
- Hook: **`pre_eval` only**, and only the **in-band** phase. Put it under `inband: pre_eval:`. In any other hook (`on_load`, `post_eval`, `on_match`, challenge hooks) the config fails to load. Source: `Hook.Build` adds `rateLimitExprOptions` only when `stage == hookPreEval`. ([appsec.go](https://github.com/crowdsecurity/crowdsec/blob/3d369d64eb3e9ba770ed39aedc83ffd3170aef4c/pkg/appsec/appsec.go), extract `.sources/appsec.go.md`)
- Out-of-band call (for example a legacy top-level `pre_eval`, which runs in both phases): no token spent, never blocks, one warning per key. ([ratelimit.go](https://github.com/crowdsecurity/crowdsec/blob/3d369d64eb3e9ba770ed39aedc83ffd3170aef4c/pkg/appsec/ratelimit.go), extract `.sources/ratelimit.go.md`)
- `key` and `limit` must be **string literals**. A key may appear in **one** `RateLimit()` call in the whole config. Units: `s`, `m`, `h` only; count a positive integer. A bad limit, a non-literal or a duplicate key stops the AppSec datasource at load. ([patcher.go](https://github.com/crowdsecurity/crowdsec/blob/3d369d64eb3e9ba770ed39aedc83ffd3170aef4c/pkg/appsec/patcher.go), extract `.sources/patcher.go.md`)
- No other config is needed: no hub parser, scenario or profile. The limiter is built from the collected calls at load time. The `crowdsecurity/appsec-rate-limit-logs` parser is only needed to write your own scenarios on the events. ([rate limiting](https://docs.crowdsec.net/docs/appsec/rate_limiting))

### Bucket keying

- **One budget per (key, client).** Each key has its own limiter; inside it, one token bucket per client. ([rate limiting](https://docs.crowdsec.net/docs/appsec/rate_limiting))
- Client = the request's client IP (`X-Crowdsec-Appsec-Ip`). IPv4 is keyed per address. IPv6 is keyed per `/64`. An optional third argument switches to that value; an empty value falls back to the IP; a value never spends an IP's budget. ([ratelimit.go](https://github.com/crowdsecurity/crowdsec/blob/3d369d64eb3e9ba770ed39aedc83ffd3170aef4c/pkg/appsec/ratelimit.go) `rateLimitIdentityFor`)
- Token bucket: `golang.org/x/time/rate` with burst = count and refill = count per period. `"2/m"` allows 2 requests at once; the 3rd is blocked; one token comes back every 30 s.
- Limiters are shared by all routines of **one AppSec datasource** (engine), held in memory, and reset when CrowdSec restarts or reloads. ([rate limiting](https://docs.crowdsec.net/docs/appsec/rate_limiting))

### What the bouncer receives

Source quote, `RateLimit()` when over the limit ([ratelimit.go](https://github.com/crowdsecurity/crowdsec/blob/3d369d64eb3e9ba770ed39aedc83ffd3170aef4c/pkg/appsec/ratelimit.go)):

```go
state.Response.InBandInterrupt = true
state.Response.Action = BanRemediation
state.Response.BouncerHTTPResponseCode = w.Config.BouncerBlockedHTTPCode
state.Response.UserHTTPResponseCode = http.StatusTooManyRequests
```

`GenerateResponse` writes `UserHTTPResponseCode` to JSON `http_status` and uses `BouncerHTTPResponseCode` as the listener status. `blocked_http_code` defaults to `403`. ([appsec.go](https://github.com/crowdsecurity/crowdsec/blob/3d369d64eb3e9ba770ed39aedc83ffd3170aef4c/pkg/appsec/appsec.go))

| Where | Value |
|---|---|
| AppSec listener HTTP status to the bouncer | `blocked_http_code` (default **403**) |
| JSON body | `{"action":"ban","http_status":429}` |

Official docs say the same: the user code is always `429 Too Many Requests` and ignores `user_blocked_http_code`; the bouncer code follows `blocked_http_code`. WAF rules are not evaluated for the blocked request. ([rate limiting](https://docs.crowdsec.net/docs/appsec/rate_limiting))

Exception (source): if an earlier `pre_eval` outcome was already recorded for the request (for example `DropRequest`), `setOutcome` refuses the second outcome. `RateLimit` then returns `true` without changing the response.

Whether the browser actually sees `429` depends on the remediation component honouring `http_status` on a `ban`. That is bouncer behavior and is outside this finding; see `ext_crowdsec_appsec_protocol/`.

## LAPI alert and decision

- **Alert: yes, once per (key, client) burst.** The first denial since that client's entry was created emits an alert to LAPI with scenario `rate limit exceeded`, scope `Ip`, value = client IP, kind `waf`, and context `rate_limit_key` / `rate_limit`. A client that keeps exceeding the limit gets no new alert until it has been idle one full period. Every denied request also emits a pipeline event (`evt.Parsed.source = crowdsec-appsec-rate-limit`). ([rate limiting](https://docs.crowdsec.net/docs/appsec/rate_limiting); [ratelimit.go](https://github.com/crowdsecurity/crowdsec/blob/3d369d64eb3e9ba770ed39aedc83ffd3170aef4c/pkg/appsec/ratelimit.go); [emit.go](https://github.com/crowdsecurity/crowdsec/blob/3d369d64eb3e9ba770ed39aedc83ffd3170aef4c/pkg/appsec/emit.go), extract `.sources/emit.go.md`: the alert "short-circuits straight to LAPI")
- **Decision: none with the default profiles.** `authority: inference`, from source:
  - `buildRateLimitAlert` sets no `Decisions` and does not set `Remediation`, so `Remediation` stays `false`. ([ratelimit.go](https://github.com/crowdsecurity/crowdsec/blob/3d369d64eb3e9ba770ed39aedc83ffd3170aef4c/pkg/appsec/ratelimit.go))
  - LAPI turns an alert without decisions into a decision only when a profile matches. ([alerts.go](https://github.com/crowdsecurity/crowdsec/blob/3d369d64eb3e9ba770ed39aedc83ffd3170aef4c/pkg/apiserver/controllers/v1/alerts.go), extract `.sources/alerts.go.md`)
  - The shipped `config/profiles.yaml` filters `Alert.Remediation == true && Alert.GetScope() == "Ip"` (or `"Range"`). ([profiles.yaml](https://github.com/crowdsecurity/crowdsec/blob/3d369d64eb3e9ba770ed39aedc83ffd3170aef4c/config/profiles.yaml), extract `.sources/profiles.yaml.md`)
  - Docs agree in substance: "we do not provide scenarios for this out of the box". A persistent ban needs your own scenario (with `remediation: true`) on the rate-limit events. ([rate limiting](https://docs.crowdsec.net/docs/appsec/rate_limiting))
- Hub: the generic `appsec-logs` parser explicitly excludes `crowdsec-appsec-rate-limit` events, so `appsec-vpatch` cannot ban on them. No hub collection pulls in `appsec-rate-limit-logs`, and no hub scenario consumes it. ([hub parsers](https://github.com/crowdsecurity/hub/blob/45ddd98db0db97d9da2b21d2bcf007b5cecd3c3f/parsers/s01-parse/crowdsecurity/appsec-rate-limit-logs.yaml), extract `.sources/hub-appsec-parsers.md`)
- What shared test instances do see: the alert row appears in `cscli alerts list`, and the limiter state persists in memory until the period refills or CrowdSec reloads. A custom profile that matches on scenario or kind (not `Remediation`) could still turn the alert into a decision.

## Minimal config and loading

Official loading path: put the file under `/etc/crowdsec/appsec-configs/` and list its `name` in the AppSec acquisition's `appsec_configs`. ([configuration](https://docs.crowdsec.net/docs/appsec/configuration), extract `.sources/configuration.md`; [AppSec datasource](https://docs.crowdsec.net/docs/log_processor/data_sources/appsec), extract `.sources/appsec-datasource.md`)

`/etc/crowdsec/appsec-configs/e2e-rate-limit.yaml` (shape from the docs Quick example):

```yaml
name: e2e/rate-limit
inband:
  pre_eval:
    - filter: req.URL.Path == "/ratelimit"
      apply:
        - RateLimit("e2e-ratelimit", "2/m")
```

Acquisition (`/etc/crowdsec/acquis.d/*.yaml`):

```yaml
source: appsec
listen_addr: 0.0.0.0:7422
appsec_configs:
  - crowdsecurity/appsec-default
  - e2e/rate-limit
labels:
  type: appsec
```

`appsec_configs` takes a list, so a local config can sit next to hub configs. The `inband:` / `pre_eval` YAML keys already exist at `v1.8.0`, but `RateLimit` itself needs the `v1.8.2` image. On older images the expression does not compile and the datasource fails to load (`authority: inference`: the helper is not registered there). ([appsec.go](https://github.com/crowdsecurity/crowdsec/blob/3d369d64eb3e9ba770ed39aedc83ffd3170aef4c/pkg/appsec/appsec.go))

## Not verified

- No run against a live `v1.8.2` container. The listener status, JSON body and absence of a decision are read from source and docs, not observed.
- That the Docker image ships the repo's `config/profiles.yaml` unchanged as `/etc/crowdsec/profiles.yaml`.
- The exact load-time error message on images older than `v1.8.2`.

## References

- Official: [rate limiting](https://docs.crowdsec.net/docs/appsec/rate_limiting), [AppSec configuration](https://docs.crowdsec.net/docs/appsec/configuration), [AppSec datasource](https://docs.crowdsec.net/docs/log_processor/data_sources/appsec), [v1.8.2 release](https://github.com/crowdsecurity/crowdsec/releases/tag/v1.8.2)
- Source: `github.com/crowdsecurity/crowdsec@3d369d64:pkg/appsec/{ratelimit.go,patcher.go,appsec.go,emit.go}`, `pkg/apiserver/controllers/v1/alerts.go`, `config/profiles.yaml`; `github.com/crowdsecurity/hub@45ddd98d:parsers/s01-parse/crowdsecurity/`
- Related: `ext_crowdsec_appsec_protocol/` (verdict envelope), `ext_crowdsec_appsec_bot-detection/` (`v1.8.0` pin)
- Extracts: `.sources/`
