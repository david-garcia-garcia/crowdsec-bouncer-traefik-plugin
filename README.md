![GitHub](https://img.shields.io/github/license/david-garcia-garcia/crowdsec-bouncer-traefik-plugin)
![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/david-garcia-garcia/crowdsec-bouncer-traefik-plugin)
![GitHub tag (latest SemVer)](https://img.shields.io/github/v/tag/david-garcia-garcia/crowdsec-bouncer-traefik-plugin)
[![Build Status](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/workflows/main.yml/badge.svg)](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions)

# Crowdsec Bouncer Traefik plugin

## What this plugin is

A CrowdSec bouncer for Traefik. For every request it decides, based on CrowdSec, whether to let the visitor through, ban them, or show them a captcha. Decisions come from community blocklists, your own CrowdSec detections, and (optionally) the CrowdSec AppSec WAF.

It is a rewrite of [maxlerebourg/crowdsec-bouncer-traefik-plugin](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin). What changed:

- **AI-first.** OpenSpec specs, a knowledge base, and intensive test coverage, including mock and real-stack harnesses.
- **Detailed metrics in CrowdSec.** Blocked requests are reported per decision origin and per blocklist, so they show up broken down in `cscli metrics` and the CrowdSec Console. See [LAPI metrics reporting](#lapi-metrics-reporting).
- **reCAPTCHA Enterprise.** Checkbox and score keys, plus classic reCAPTCHA, hCaptcha, Turnstile, and custom widgets.
- **EU CAPTCHA.** Provider `eucaptcha`.
- **Self-hosted custom captchas.** With `captchaProvider: custom`, the widget script and challenge endpoint (`captchaCustomJsUrl`, `captchaCustomChallengeUrl`) can sit behind the protected router: visitors waiting for a captcha can still load them. The answer can also be validated with a JSON body (`captchaCustomValidateBody: json`), as [Cap](https://capjs.js.org/) expects. See [Variables](#variables).
- **Captcha passes stored on the visitor.** A solved captcha is remembered with a signed cookie on that browser (optionally tied to its IP). The original plugin whitelisted the IP on the server, so one solve let in every browser behind that address, and multi-instance setups needed Redis to share it.
- **No Redis needed.** The recommended setup keeps decisions in memory. Redis is only useful for the `live` LAPI mode with several Traefik replicas.
- **Per-router settings.** Each router keeps its own status code, captcha, trusted IPs, and behavior when CrowdSec is down. The original plugin shared one set of settings across every CrowdSec middleware in Traefik.
- **Captcha when CrowdSec is down.** `bouncerLapiFailureAction` and `bouncerAppsecFailureAction` choose `ban`, `passthrough`, or `captcha` when LAPI or AppSec cannot answer. The original plugin could only block or let the request through. See [Choose what happens when CrowdSec is down](#choose-what-happens-when-crowdsec-is-down).
- **Soften a ban per origin with `bouncerOriginBasedDecisionRemap`.** On one router, turn a ban from a chosen origin into a captcha or a pass: the community blocklist, every blocklist, or one named list. Other routers sharing the same LAPI connection keep the original ban. See [Show a community ban as a captcha](#show-a-community-ban-as-a-captcha).
- **Several CrowdSec engines** in one Traefik, each with its own API key, or several routers sharing one engine. See [Middleware Architecture](#middleware-architecture).
- **Config reloads apply.** Changing the LAPI host, key, mode, interval, or any other setting takes effect on a Traefik configuration reload. The original plugin kept the first values until Traefik restarted.
- **IP, IP range, country, ASN, and custom scopes.** The original plugin matched the client IP only.
- **Forwarded IP header trusted only from listed proxies.** With `bouncerForwardedHeadersTrustedIps` empty, the plugin checks the connecting IP; reading the header from any peer requires `bouncerForwardedHeadersInsecure`. The original plugin read the header from any peer when that list was empty. See [Remediate the visitor, not the proxy](#remediate-the-visitor-not-the-proxy).
- **AppSec independent of the LAPI mode.** A router can run the WAF, the decision lookup, or both.
- **Client certificates for AppSec.** `appsecTlsClientCertificate` and `appsecTlsClientKey` authenticate the plugin to AppSec with mTLS, as LAPI already allowed. The original plugin did not support mTLS for AppSec. See [Use HTTPS to communicate with the Appsec](#use-https-to-communicate-with-the-appsec).
- **Separate timeouts.** LAPI, AppSec, and captcha validation each have their own (`lapiHttpTimeoutSeconds`, `appsecHttpTimeoutSeconds`, `captchaSiteverifyHttpTimeoutSeconds`), so a short AppSec timeout does not cut LAPI calls short. The original plugin used one `httpTimeoutSeconds` for all three.
- **Permanent rules with `bouncerActionRules`.** Ban, captcha, or skip checks for requests matching a path, host, method, header, or cookie, without any CrowdSec decision. For example, always show a captcha to a whole country or region by matching a country header such as `CF-IPCountry`, or skip all checks for a specific host. See [BouncerActionRules](#variables).
- **No captcha on API routes with `bypassCaptcha`.** A `bouncerActionRules` action for requests that cannot solve a captcha, such as API calls from another server: where a captcha would be served, the request goes through. Bans still apply. See [Keep captchas off API routes](#keep-captchas-off-api-routes).
- **Detailed verdict header.** `bouncerRemediationHeadersCustomName` now tells not only what was done (ban or captcha) but why and from where: a CrowdSec decision and its origin (`ban:lapi:CAPI`, `ban:lapi:lists_firehol_level1`), AppSec, a rule, or an outage of LAPI or AppSec. Add it to your access logs to trace every blocked request back to its cause. The original plugin only sent `ban` or `captcha`. See [See the verdict in access logs](#see-the-verdict-in-access-logs).

> [!TIP]
>
> **Traefik Security**
>
> The basic middlewares you need to secure your Traefik ingress:
>
> - 🌍 **Geoblock**: [david-garcia-garcia/traefik-geoblock](https://github.com/david-garcia-garcia/traefik-geoblock) - Block or allow requests based on IP geolocation
> - 🛡️ **CrowdSec**: [david-garcia-garcia/crowdsec-bouncer-traefik-plugin](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin) - Real-time threat intelligence and automated blocking
> - 🔒 **ModSecurity CRS**: [david-garcia-garcia/traefik-modsecurity](https://github.com/david-garcia-garcia/traefik-modsecurity) - Web Application Firewall with OWASP Core Rule Set
> - 🚦 **Ratelimit**: [Traefik Rate Limit](https://doc.traefik.io/traefik/reference/routing-configuration/http/middlewares/ratelimit/) - Control request rates and prevent abuse

> [!WARNING]
>
> **Do not run middlewares as Yaegi plugins in production.**
>
> Traefik's catalog loads plugins with [Yaegi](https://github.com/traefik/yaegi), a Go interpreter. A middleware runs on every request, so the interpreter's cost lands on every request too: memory, CPU, and observability ([Yaegi #1712](https://github.com/traefik/yaegi/pull/1712)). For real traffic, compile the middleware into the Traefik binary, for example with [traefik-with-plugins](https://github.com/david-garcia-garcia/traefik-with-plugins). Discussion: [Traefik #12213](https://github.com/traefik/traefik/issues/12213).

## What CrowdSec is

<img src="https://docs.crowdsec.net/img/crowdsec_logo.png" alt="CrowdSec" height="80">

> [CrowdSec](https://www.crowdsec.net/) is an open-source and collaborative IPS (Intrusion Prevention System) and a security suite.
> We leverage local behavior analysis and crowd power to build the largest CTI network in the world.

CrowdSec also provides the community blocklist: IPs that are widely reported and validated as malicious across the CrowdSec network.

A few CrowdSec terms used in this README:

- **LAPI** (Local API): the CrowdSec service that stores decisions ("ban this IP for 4 hours"). This plugin reads decisions from it.
- **CAPI** (Central API): CrowdSec's cloud service that distributes the community blocklist.
- **AppSec**: CrowdSec's WAF component. It inspects a single request and answers allow or block.
- **Bouncer**: a component that enforces decisions. This plugin is a bouncer.

## Architecture diagram

```mermaid
flowchart LR
  User["User"]
  Traefik["Traefik"]
  Plugin["This plugin"]
  Origin["Protected app"]
  Logs["Traefik access logs"]
  Engine["CrowdSec engine"]
  LAPI["LAPI"]
  CAPI["CAPI / community lists"]
  AppSec["AppSec"]

  User -->|"HTTP request"| Traefik
  Traefik -->|"User Http Request"| Plugin
  Plugin -->|"User Http Request"| Origin
  Plugin -->|"ban / captcha"| User
  Traefik -->|"writes"| Logs
  Logs -->|"acquis / ingest"| Engine
  Engine -->|"decisions"| LAPI
  CAPI -->|"remote blocklists"| LAPI
  LAPI -->|"decision lookup"| Plugin
  Plugin -.->|"this request?"| AppSec
  AppSec -.->|"allow / block"| Plugin
```

Users are blocked based on:

- Remote decisions (threat intelligence)
- Local decisions from inspecting your Traefik access logs and identifying attack patterns
- AppSec WAF

This plugin only enforces decisions. It does not read logs; CrowdSec does that and produces the decisions.

To share one CrowdSec connection between routers, or to use several CrowdSec engines in one Traefik, see [Middleware Architecture](#middleware-architecture).

## Decisions

A CrowdSec decision says *who* (the scope, e.g. an IP) and *what to do* (the remediation, e.g. ban).

Supported scopes:

- `Ip`: the client IP.
- `Range`: an IP range (CIDR) that contains the client IP.
- Any other scope (country, ASN, username, …) read from a request header you configure in `bouncerDecisionScopeHeaders`.

`bouncerDecisionScopeHeaders` maps a CrowdSec **scope name** (the key) to the **request header** that holds the value (the value). The key also decides how the header is compared:

- `Country` (any case): two-letter ISO country code, case-insensitive. Cloudflare's `XX` and `T1` never match. Example headers: `CF-IPCountry`, or `X-IPCountry` from a geolocation middleware.
- `AS` (any case): ASN number. A leading `AS` (as in `AS13335`) is ignored. Example header: `CF-ASN`.
- Any other key (`username`, `session`, …): the header value, trimmed, compared exactly. The key must match the scope name stored in CrowdSec (`username` is not `user`).
- `Ip` and `Range` cannot be mapped to a header; they always use the client address.

```yaml
bouncerDecisionScopeHeaders:
  Country: X-IPCountry
  AS: CF-ASN
  username: X-User
```

The plugin does not geolocate. Header values are used as received, so they must come from something you trust: a CDN, a reverse proxy, or an earlier Traefik middleware such as [traefik-geoblock](https://github.com/david-garcia-garcia/traefik-geoblock). If visitors can set the header themselves, they can dodge or trigger these decisions. A complete example is in [examples/geoenrich-decisions](examples/geoenrich-decisions/README.md).

## Remediation

What the visitor gets for each CrowdSec remediation ([CrowdSec bouncers](https://docs.crowdsec.net/u/bouncers/intro)):

| Remediation | What the user gets |
| ----------- | ------------------ |
| `ban`       | A ban page (or an empty body) with status `bouncerRemediationStatusCode` (default 403). An AppSec ban keeps the `http_status` CrowdSec sends instead: 403 by default, 429 for a `RateLimit()` block, or the code set with `user_blocked_http_code` or `SetReturnCode()`. |
| `captcha`   | A captcha page. Once solved, the visitor is redirected back to the page they asked for and is not challenged again for `captchaGracePeriodSeconds` (default 24 hours). See [examples/captcha](examples/captcha/README.md). |

Captcha providers:

- [hCaptcha](https://www.hcaptcha.com/) (`hcaptcha`)
- [reCAPTCHA](https://www.google.com/recaptcha/about/) (`recaptcha`)
- [reCAPTCHA Enterprise](https://cloud.google.com/recaptcha/docs/introduction) (`recaptcha-enterprise`)
- [Turnstile](https://www.cloudflare.com/products/turnstile/) (`turnstile`)
- [EU CAPTCHA](https://eu-captcha.eu/) (`eucaptcha`)
- Any other widget, for example [Wicketkeeper](https://github.com/a-ve/wicketkeeper) (`custom`)

To serve captchas, set `captchaEnabled: true` together with the `captcha*` settings. Setting only `captchaProvider` is not enough.

The page that ships with the plugin is ready to use. It shows the site name, asks the visitor to verify they are human, and embeds the provider widget. Set `captchaFilePath` only if you want your own HTML.

![Built-in captcha page: the site name, a verify-you-are-human prompt, and the provider widget](.assets/captcha.png)

## AppSec

This plugin supports [AppSec](https://doc.crowdsec.net/docs/next/appsec/intro/), CrowdSec's WAF, which offers:

- Low-effort virtual patching.
- Support for your existing ModSecurity rules.
- Classic WAF protection combined with CrowdSec's behavior detection.

AppSec requires CrowdSec 1.6.0 or later.

**Bot detection (CrowdSec 1.8+).** CrowdSec can answer a suspicious request with a JavaScript challenge page instead of a ban. This works out of the box once AppSec is enabled. The challenge page calls back to URLs under `/crowdsec-internal/challenge/`, and those calls must go through this middleware so CrowdSec can verify them. The proof is POSTed to `/crowdsec-internal/challenge/submit` and must reach AppSec with the full form. The default `appsecBodyLimit` of 10MB is enough. A smaller positive limit cuts the proof short. `0` means no limit: the whole body is sent. When AppSec is enabled, this plugin never forwards that prefix to origin: whatever AppSec does not answer there is 404. A `bypass` or `bypassAppsec` action rule never skips AppSec on that prefix, so a rule such as `\.js$` for static files does not break the challenge. If the middleware already covers every path of the host, you are done. If it only covers some paths (for example `/api`), add a router for ``PathPrefix(`/crowdsec-internal/challenge`)`` with the same middleware. A Content-Security-Policy set by a `headers` middleware listed before this one breaks the challenge: see [Keep a Content-Security-Policy without breaking the challenge or the captcha](#keep-a-content-security-policy-without-breaking-the-challenge-or-the-captcha). See [CrowdSec bot detection](https://docs.crowdsec.net/docs/next/appsec/bot_detection/intro.md).

**Captcha from AppSec.** An AppSec rule or hook can ask for a captcha instead of a ban (`SetRemediation("captcha")`). CrowdSec sends no page with that answer, so the router serves its own captcha, the same one it uses for a CrowdSec captcha decision. Configure a captcha provider on that router; without one, the visitor gets the ban page (`ban:captcha-downgrade`). A solved captcha lets the visitor through AppSec captchas for the grace period; AppSec bans still apply. The captcha form posts back to the same URL and goes through AppSec first. If AppSec lets that POST through, the plugin still recognises it by the hidden field `crowdsec_captcha_challenge=v1` and checks the answer, so a replaced captcha template must keep that field. AppSec actions this plugin does not know, sent without a page, are served as a ban (`ban:appsec-action-empty`).

More information in the [CrowdSec AppSec documentation](https://doc.crowdsec.net/docs/next/appsec/intro/).

## LAPI modes

`lapiMode` controls how the plugin gets decisions from LAPI. Sequence diagrams are in [docs/modes.md](docs/modes.md).

| LAPI mode | How it works |
| --------- | ------------ |
| `stream`  | Downloads all decisions from LAPI and refreshes them on an interval. Requests are checked against memory only. **Recommended.** |
| `live`    | Asks LAPI about each new client IP and caches the answer for a while. |
| `none`    | Asks LAPI on every request. No cache. |
| `alone`   | Like `stream`, but downloads the community blocklist directly from CAPI. No local CrowdSec needed. |

`stream` is recommended:

- Requests never wait on LAPI; decisions are refreshed every 60 seconds by default (`lapiUpdateIntervalSeconds`).
- Expect around 20 MB of memory for a full decision stream, community blocklist included.
- The plugin still sends usage metrics to LAPI every `lapiMetricsUpdateIntervalSeconds` (set it to `0` to turn metrics off).

To run AppSec without any decision lookup, set `lapiEnabled: false` and `appsecEnabled: true` (see [AppSec only](#appsec-only)).

## LAPI metrics reporting

The plugin reports what it did back to CrowdSec through LAPI's usage-metrics endpoint, every `lapiMetricsUpdateIntervalSeconds` (default 10 minutes). It reports:

- Requests processed, split by IPv4 and IPv6.
- Requests dropped, split by remediation (ban or captcha) and by **decision origin**: your own CrowdSec detections, manual `cscli` decisions, the community blocklist (CAPI), and each subscribed blocklist on its own.
- The number of active decisions held in memory.

You can read these with `cscli metrics show bouncers`, and the CrowdSec Console shows them per origin:

![CrowdSec Console: requests dropped per origin](.assets/dashboard_origins.jpg)

## Middleware Architecture

Most installs need a single middleware with everything enabled (see [One middleware](#one-middleware-all-in-one)). Read the rest of this section if you protect several routers with different settings, or use several CrowdSec engines.

A middleware can do two jobs:

1. **Connect** to CrowdSec. Each connection is turned on separately and is shared under a name, which defaults to the middleware's own name:

   | Connection | Turn on with | Shared as |
   | ---------- | ------------ | --------- |
   | LAPI (decisions) | `lapiEnabled: true` | `lapiInstanceName` |
   | AppSec (WAF) | `appsecEnabled: true` | `appsecInstanceName` |
   | Captcha provider | `captchaEnabled: true` | `captchaInstanceName` |

2. **Protect** the router it is attached to (`bouncerEnabled: true`), using the connections it names.

A middleware that only protects sets `bouncerEnabled: true` plus the instance names it wants to use, and leaves the `*Enabled` connection flags off. It does not repeat the host, key, or interval: those live on the middleware that connects. It keeps its own request settings (status code, captcha, trusted IPs, behavior when CrowdSec is down, response headers). LAPI, AppSec, and captcha names are independent, so all three can be called `shared`.

```mermaid
flowchart LR
  subgraph traefik ["One Traefik process"]
    B1["Bouncer /api"]
    B2["Bouncer /admin"]
    B3["Bouncer /tenant-b"]
    L1["LAPI client shared"]
    L2["LAPI client tenant-b"]
    A1["AppSec client shared"]
  end
  CS1["CrowdSec engine A"]
  CS2["CrowdSec engine B"]
  B1 --> L1
  B2 --> L1
  B1 --> A1
  B2 --> A1
  B3 --> L2
  L1 --> CS1
  A1 --> CS1
  L2 --> CS2
```

Right after Traefik starts or reloads, a connection can take a moment to become available. Until it does, a request that needs that connection uses the configured failure action.

### One middleware (all-in-one)

No instance names needed: the middleware connects and protects on its own.

```yaml
api-crowdsec:
  plugin:
    bouncer:
      appsecEnabled: true
      appsecKey: "..."
      bouncerEnabled: true
      lapiEnabled: true
      lapiHost: crowdsec:8080
      lapiKey: "..."
      lapiMode: stream
```

### Shared connection, per-router settings

`cs` connects to LAPI and AppSec and shares both as `shared`. `cs-admin` reuses them and only adds its own setting.

```yaml
cs:
  plugin:
    bouncer:
      appsecEnabled: true
      appsecInstanceName: shared
      appsecKey: "..."
      bouncerEnabled: true
      lapiEnabled: true
      lapiHost: crowdsec:8080
      lapiInstanceName: shared
      lapiKey: "..."
      lapiMode: stream
cs-admin:
  plugin:
    bouncer:
      appsecInstanceName: shared
      bouncerEnabled: true
      bouncerRemediationHeadersCustomName: x-crowdsec
      lapiInstanceName: shared
```

If you prefer the connections to live in a middleware that protects nothing, set `bouncerEnabled: false` on it. It still has to be attached to some router, or Traefik never loads it.

```yaml
cs-holders:
  plugin:
    bouncer:
      appsecEnabled: true
      appsecInstanceName: shared
      appsecKey: "..."
      bouncerEnabled: false
      lapiEnabled: true
      lapiHost: crowdsec:8080
      lapiInstanceName: shared
      lapiKey: "..."
      lapiMode: stream
```

### Several LAPI streams or CrowdSec engines

CrowdSec tracks one stream per combination of **bouncer API key and the IP Traefik connects from**. Two LAPI connections with the same key from the same Traefik interfere with each other. Each separate stream needs its own bouncer key (and its own host if it is another engine).

Give each connection its own name, and point each protecting middleware at the one it should use:

```yaml
cs-a:
  plugin:
    bouncer:
      bouncerEnabled: true
      lapiEnabled: true
      lapiHost: crowdsec-a:8080
      lapiInstanceName: engine-a
      lapiKey: "key-a"
      lapiMode: stream
cs-b:
  plugin:
    bouncer:
      bouncerEnabled: true
      lapiEnabled: true
      lapiHost: crowdsec-b:8080
      lapiInstanceName: engine-b
      lapiKey: "key-b"
      lapiMode: stream
app-a:
  plugin:
    bouncer:
      bouncerEnabled: true
      lapiInstanceName: engine-a
app-b:
  plugin:
    bouncer:
      bouncerEnabled: true
      lapiInstanceName: engine-b
```

`app-a` and `app-b` run in the same Traefik but see different decisions. The same pattern works for two streams from one engine, using two bouncer keys.

### AppSec only

No decision lookup; only the WAF.

```yaml
waf:
  plugin:
    bouncer:
      appsecEnabled: true
      appsecHost: crowdsec:7422
      appsecKey: "..."
      bouncerEnabled: true
      lapiEnabled: false
```

## Cache

The cache keeps CrowdSec decisions so the plugin does not ask LAPI on every request.

- **`stream` / `alone`**: the full decision list is kept in memory. Redis is supported but not recommended here: it adds a network hop for data already refreshed on an interval.
- **`live`**: each client's answer (banned, captcha, or clean) is kept for `lapiDefaultDecisionSeconds`. With several Traefik replicas, a shared Redis lets them reuse each other's answers.
- **`none`**: no cache.

Solved captchas are not stored in this cache; they are remembered with a signed cookie on the visitor's browser.

## What you can do

Common tasks and the settings behind them. The [Variables](#variables) list is the full reference.

### Test a ban or a captcha from the browser

`bouncerActionRules` can force a ban or a captcha when a request carries a header you choose:

```yaml
bouncerActionRules:
  - name: decision-ban
    headers:
      X-Crowdsec-Decision: "^b$"
    action: [ban]
  - name: decision-captcha
    headers:
      X-Crowdsec-Decision: "^c$"
    action: [captcha]
captchaEnabled: true
captchaProvider: hcaptcha
captchaSiteKey: FIXME
captchaSecretKey: FIXME
captchaGateSecret: FIXME
bouncerEnabled: true
```

Header values are regular expressions, so use `^b$` for an exact match (a bare `b` also matches `abc`).

Then send the header yourself, with a browser header extension, DevTools, or `curl`:

```bash
curl -D - -H "X-Crowdsec-Decision: b" https://app.example/
curl -D - -H "X-Crowdsec-Decision: c" https://app.example/
```

| Value | What you get |
| ----- | ------------ |
| `b` | Ban immediately, with status `bouncerRemediationStatusCode` (default 403). CrowdSec is not consulted. |
| `c` | A captcha, unless CrowdSec bans the client anyway (a ban always wins). Use `action: [captcha, bypass]` to skip the CrowdSec checks and always get the captcha. |
| anything else | No rule matches; the request is checked normally. |

Once you solve the captcha, you will not see it again until the grace period ends. Delete the `crowdsec_captcha_gate` cookie to get challenged again.

Clients listed in `bouncerClientTrustedIps` skip the plugin entirely, including these rules, so test from another address.

Do not leave a header that visitors can set on a public route: anyone could ban or captcha their own requests. Either have an earlier middleware set the header only for traffic you control, or use it on a staging router and remove it afterwards.

You can also test with a real decision: see [Manually add an IP to the blocklist](#manually-add-an-ip-to-the-blocklist-for-testing-purposes).

### See the verdict in access logs

Set `bouncerRemediationHeadersCustomName` to a header name, and the plugin adds that header to every response it blocks or challenges. Add the same name to Traefik's `accessLog.fields.headers` to see it in your logs.

```yaml
bouncerRemediationHeadersCustomName: cs-remediation
```

The value is `what:why` or `what:why:origin`, separated by colons with no spaces:

| Value | Meaning |
| ----- | ------- |
| `ban:rules` | Banned by a `bouncerActionRules` rule. |
| `ban:lapi` / `ban:lapi:<origin>` | Banned by a CrowdSec decision. The third field is the decision origin (`crowdsec`, `cscli`, `CAPI`, or `lists_<name>` for a blocklist). |
| `ban:lapi-failure` | LAPI was unreachable, and the failure action is `ban`. |
| `ban:stream-unhealthy` | Decisions could not be refreshed for too long, and the failure action is `ban`. |
| `ban:cache-fail` | Redis was unreachable. |
| `ban:appsec` | Blocked by AppSec. |
| `ban:appsec-challenge-empty` | AppSec asked for a bot challenge but sent no page, so a ban was served instead. |
| `ban:appsec-action-empty` | AppSec returned an action this plugin cannot show (for example a custom `SetRemediation("tarpit")`) and sent no page, so a ban was served instead. |
| `ban:appsec-failure` | AppSec was unreachable, and the failure action is `ban`. |
| `ban:captcha-downgrade` | A captcha was due, but this router has no captcha configured, so a ban was served. |
| `captcha:rules` | Captcha from a `bouncerActionRules` rule. |
| `captcha:lapi` / `captcha:lapi:<origin>` | Captcha from a CrowdSec decision. |
| `captcha:lapi-failure` | LAPI was unreachable, and the failure action is `captcha`. |
| `captcha:stream-unhealthy` | Decisions could not be refreshed for too long, and the failure action is `captcha`. |
| `captcha:appsec-failure` | AppSec was unreachable, and the failure action is `captcha`. |
| `captcha:appsec` | AppSec asked for a captcha, and this router served its own captcha page. |
| `captcha:challenge` | AppSec served a bot-detection challenge. |
| `captcha:solved` | The visitor just solved the captcha and is being redirected back. |
| `error:client-disconnected` | The client disconnected while AppSec was reading the request body. Not a ban. |
| `error:client-body-read` | The request body could not be read whole for AppSec while the client was still connected (for example an upload slower than the entry point read timeout). Answered HTTP 400 `Bad Request`. Not a ban. |
| `<action>:appsec` | Any other action returned by AppSec. |

Requests that are let through get no header. A client address that cannot be read (`RemoteAddr` is not `host:port`, or the chosen text is not an IP) is HTTP 502 `Bad Gateway`, also with no header.

### Put a request id on the ban page

`bouncerTraceHeadersCustomName` copies one request header into the ban page as `{{ .TraceID }}`, so visitors can quote it to support.

```yaml
bouncerTraceHeadersCustomName: X-Request-ID
bouncerBanFilePath: /ban.html
```

Only values made of letters, digits, `_`, `.`, `:`, and `-` (up to 200 characters) are inserted; anything else is left out, so the header cannot inject markup.

The ban template can also use:

- `{{ .ClientIP }}` — the visitor's IP
- `{{ .Domain }}` — the requested host
- `{{ .RemediationReason }}` — `LAPI`, `APPSEC`, or `TECHNICAL_ISSUE`

A sample page is in [examples/custom-ban-page](examples/custom-ban-page/README.md). Without `bouncerBanFilePath`, a ban is just the status code with an empty body.

### Show a community ban as a captcha

`bouncerOriginBasedDecisionRemap` softens decisions from specific origins on this router only. For example, to show a captcha instead of a ban to IPs from the community blocklist or from one list:

```yaml
bouncerOriginBasedDecisionRemap:
  CAPI:
    ban: captcha
  lists:firehol_level1:
    ban: captcha
```

- The outer key is the origin: `CAPI` (community blocklist), `lists` (every blocklist), or `lists:<name>` (one blocklist).
- The inner key is what CrowdSec decided (`ban` or `captcha`); the value is what this router does instead (`captcha` or `pass`).
- `pass` lets the request through the decision check; AppSec still runs if enabled.
- Rules do not chain: with `ban: captcha` and `captcha: pass`, a ban becomes a captcha, not a pass.

The router needs a captcha configured; otherwise the remapped captcha is served as a ban. Two routers sharing one LAPI connection can remap differently.

### Keep a Content-Security-Policy without breaking the challenge or the captcha

Two pages served by this plugin need scripts that a strict Content-Security-Policy (CSP) blocks:

- The AppSec bot-detection challenge runs inline scripts and a `blob:` worker. CrowdSec sends the CSP it needs with every challenge, and the plugin replaces any CSP already on the response with it, as the [challenge protocol](https://docs.crowdsec.net/docs/next/appsec/bot_detection/challenge_protocol/) requires.
- The captcha page loads the provider's script (hCaptcha, reCAPTCHA, Turnstile, …) from the provider's domain and runs inline scripts.

If your policy forbids them, the visitor gets a blank page or a captcha that never shows, and the browser console reports `Refused to execute inline script` or `Refused to load the script`. The challenge or the captcha can never be solved.

Where you list Traefik's `headers` middleware decides whether your policy reaches these pages. That middleware does not set its response headers when the request passes through it. It sets them when the response is written, on top of whatever the middlewares after it set. This holds for `contentSecurityPolicy` and for `customResponseHeaders`.

- Listed **before** this plugin, it overwrites the challenge's CSP and also applies to the captcha page. No setting of this plugin can prevent it.
- Listed **after** this plugin, it never runs when the plugin answers (ban, captcha, challenge), so those pages get none of its headers. Responses from your application still get them.

Put your CSP in its own `headers` middleware listed after this plugin. Your other security headers (HSTS, `X-Frame-Options`, …) can stay in one listed before it, so they reach every page:

```yaml
http:
  routers:
    my-router:
      rule: Host(`app.example`)
      service: my-service
      middlewares:
        - security-headers # before: every response, plugin pages included
        - crowdsec
        - csp # after: only responses from your application
  middlewares:
    security-headers:
      headers:
        frameDeny: true
        stsSeconds: 31536000
    csp:
      headers:
        contentSecurityPolicy: "default-src 'self'"
```

The ban and captcha pages then have no CSP. To give them one, put a `<meta http-equiv="Content-Security-Policy">` tag in your own template (`bouncerBanFilePath`, `captchaFilePath`). On the captcha page it must allow the provider's script and the inline scripts.

CrowdSec describes the same conflict, and the nginx setup, in [enabling bot detection](https://docs.crowdsec.net/docs/next/appsec/bot_detection/enable#content-security-policy).

### Keep captchas off API routes

A captcha is a web page for a person. A script, a mobile app, or another server calling your API cannot solve it. It receives the captcha HTML with HTTP 200 where it expected its API response. This happens, for example, when a CrowdSec `captcha` decision covers a whole network (AS) and your own integration calls the API from an address in that network.

The `bypassCaptcha` action lets matching requests through wherever this router would have served a captcha. Bans still apply.

```yaml
bouncerActionRules:
  - name: api-no-captcha
    path: "^/api/"
    action: [bypassCaptcha]
```

The rule skips no check. The plugin still looks up CrowdSec decisions and still queries AppSec for these requests. Only the captcha answer changes: the request continues to the next check and then to your application. It gets no remediation header and is not counted as dropped.

**Where it applies.** On a matching request, each of these lets the request through:

| A captcha would have been served because | Header it would have carried |
| ---------------------------------------- | ---------------------------- |
| A CrowdSec decision of type `captcha` matches the client (its IP, range, country, AS, or a custom scope). | `captcha:lapi`, `captcha:lapi:<origin>` |
| LAPI is unreachable, or decisions could not be refreshed, and `bouncerLapiFailureAction` is `captcha`. | `captcha:lapi-failure`, `captcha:stream-unhealthy` |
| AppSec answered `captcha`. | `captcha:appsec` |
| AppSec is unreachable and `bouncerAppsecFailureAction` is `captcha`. | `captcha:appsec-failure` |
| Another matching rule has the `captcha` action. | `captcha:rules` |
| A captcha was due and this router has no captcha configured, so a ban would have been served. | `ban:captcha-downgrade` |

**Where it does not apply.** These are unchanged on a matching request:

| Case | What happens |
| ---- | ------------ |
| Any ban: a CrowdSec `ban` decision, an AppSec block, a `ban` rule, a failure action `ban`, Redis unreachable. | The request is banned. |
| A ban that `bouncerOriginBasedDecisionRemap` softens to a captcha (`ban: captcha`). | It stays a ban on these requests. Otherwise a ban would end as a pass. A remap `ban: pass` still lets the request through. |
| The AppSec bot-detection challenge (`captcha:challenge`). | It is still served. It is AppSec's own page, not this router's captcha, although its header value starts with `captcha:`. |
| A request the rule does not match. | It gets the captcha as before. |
| A client in `bouncerClientTrustedIps`. | It skips the whole plugin, these rules included. |

`captcha` and `bypassCaptcha` in the same rule are rejected when the configuration loads.

Match on what the client cannot choose for another resource: the path, the host, the method. Do not write a `bypassCaptcha` rule on a header or a cookie the client sets, such as `User-Agent` or `X-Requested-With`. Any visitor could add it and skip the captcha on every page.

**What you give up.** On the matching requests a captcha no longer slows anyone down. A client that CrowdSec wanted to challenge can call those routes freely, and during a LAPI or AppSec outage with failure action `captcha` they are let through as with `passthrough`. Only bans stop a client there. If one known integration is the reason for the rule and it has a fixed address, [`bouncerClientTrustedIps`](#let-a-lan-or-vpn-through) for that address is the narrower setting.

**How the path is matched.** The `path` pattern runs as written on the path the plugin receives, for every request. The other skip actions (`bypass`, `bypassLapi`, `bypassAppsec`) switch themselves off on a path with percent-encoding or other ambiguous characters. `bypassCaptcha` does not, so `/api/items%20x` works. It relies on Traefik having cleaned the path first. Measured on Traefik v3.7.11 and v3.7.19 with the rule above:

| Request sent | Path the plugin and your application receive | Captcha bypassed |
| ------------ | -------------------------------------------- | ---------------- |
| `/api/../admin`, `/api/%2e%2e/admin`, `/api/..\admin` | `/admin` | No. Traefik resolved the path before the plugin. |
| `/api/..;/admin` | `/admin` from Traefik v3.7.18. Unchanged on earlier versions. | No from v3.7.18. Yes on earlier versions. |
| `/api/..%2Fadmin`, `/api/..%5Cadmin`, `/api/..%3B/admin`, `/api/%252e%252e/admin` | Unchanged | Yes |

The last row is the limit. Traefik does not decode `%2F` (`/`), `%5C` (`\`), `%3B` (`;`) or `%25` (`%`) by default, so the request still starts with `/api/` and the rule matches. Your application receives the same encoded path. If it decodes those characters and then resolves `..`, it serves `/admin` to a client that should have seen a captcha. Anchoring the pattern does not prevent this. Bans are not affected: a banned client stays banned on every path.

To close it, make Traefik reject those encoded characters on the entry point. It then answers HTTP 400 before the plugin runs:

```yaml
# Traefik static configuration (CLI flags)
- "--entrypoints.websecure.http.encodedCharacters.allowEncodedSlash=false"
- "--entrypoints.websecure.http.encodedCharacters.allowEncodedBackSlash=false"
- "--entrypoints.websecure.http.encodedCharacters.allowEncodedSemicolon=false"
- "--entrypoints.websecure.http.encodedCharacters.allowEncodedPercent=false"
```

Check first that no legitimate URL of your application uses them, for example an identifier that contains an encoded `/`. See [Request Path](https://doc.traefik.io/traefik/security/request-path/) in the Traefik documentation.

### Let a LAN or VPN through

`bouncerClientTrustedIps` lets these client addresses skip all checks, AppSec included. See [examples/trusted-ips](examples/trusted-ips/README.md).

```yaml
bouncerClientTrustedIps:
  - 192.168.1.0/24
```

The address checked is the [real client IP](#remediate-the-visitor-not-the-proxy), not the proxy's, when a trusted proxy is configured.

### Remediate the visitor, not the proxy

Behind Cloudflare, a load balancer, or another reverse proxy, every connection comes from the proxy. Unless you tell the plugin to trust the proxy, every visitor is treated as the proxy's IP.

List the proxy's addresses in `bouncerForwardedHeadersTrustedIps` and set `bouncerForwardedHeadersCustomName` to the header that proxy sends with the real client IP (`CF-Connecting-IP`, `X-Forwarded-For`, or `X-Real-Ip`). See [examples/behind-proxy](examples/behind-proxy/README.md), and the variable descriptions below for details.

### Choose what happens when CrowdSec is down

`bouncerLapiFailureAction` and `bouncerAppsecFailureAction` decide what happens when LAPI or AppSec cannot give an answer:

- `ban` (default) — block the request.
- `passthrough` — let it through. If LAPI is down, AppSec still checks the request.
- `captcha` — show a captcha. Requires a captcha on this router.

When the LAPI failure action applies depends on the LAPI mode:

- **`stream` and `alone`.** The plugin keeps using the decisions it already has when LAPI is down. The failure action only applies to clients without a known decision, after `lapiUpdateMaxFailure` failed refreshes.
- **`live` and `none`.** A client that is not in the cache is looked up in LAPI on the request itself (`none` has no cache). If LAPI does not answer, the failure action applies to that request right away. There is no failure counter, so `lapiUpdateMaxFailure` has no effect. The failed lookup is not cached: the next request asks LAPI again. In `live`, decisions already in the cache keep applying until they expire.

In every mode, the failure action also applies while the connection is not published yet, including right after startup or a reload.

To let traffic through while LAPI is down in `live` or `none`, set `bouncerLapiFailureAction: passthrough`. The original plugin used `updateMaxFailure: -1` for this. That key does not exist here, and Traefik ignores unknown keys without an error.

### Match a country or an ASN

`bouncerDecisionScopeHeaders` reads the country or ASN from a header you trust; the plugin does not geolocate. `lapiStreamScopes` asks LAPI to include those decisions in the stream:

```yaml
bouncerDecisionScopeHeaders:
  Country: CF-IPCountry
  AS: CF-ASN
lapiStreamScopes:
  - country
  - as
```

`lapiStreamScopes` goes on the middleware that connects to LAPI (`lapiEnabled: true`). `bouncerDecisionScopeHeaders` goes on every middleware that protects a router. See [examples/geoenrich-decisions](examples/geoenrich-decisions/README.md).

## Usage

To get started, use the `docker-compose.yml` file.

You can run it with:

```bash
make run
```

> [!WARNING]
> AppSec only receives the first 10 MB of a request body by default (`appsecBodyLimit`).

### Variables

Names below are written as Go fields. In YAML and Docker labels, use lower camel case, with acronyms written as words: `HTTP`→`Http`, `TLS`→`Tls`, `IP`→`Ip`, `URL`→`Url`, `ID`→`Id`. For example, **BouncerClientTrustedIPs** is `bouncerClientTrustedIps`.

Secrets and certificates can also be read from a file: add `File` to the name (`lapiKey` → `lapiKeyFile`). If both are set, the file wins. See [Fill variable with value of file](#fill-variable-with-value-of-file).

**BouncerBanFilePath** (string, default `""`)
Path to the ban page. Empty means no page (status code only). Content-Type is inferred from the extension.

**CaptchaCustomChallengeUrl** (string, default `""`)
`custom` only. Challenge URL of the widget (Wicketkeeper: `http://captcha.localhost:8000/v0/challenge`), available in the template as `{{ .ChallengeURL }}`. Visitors who must solve a captcha are allowed to request this exact path.

**CaptchaCustomJsUrl** (string, no default)
`custom` only. Script URL that loads the widget (hCaptcha: `https://hcaptcha.com/1/api.js`). If it is served from the protected router, visitors who must solve a captcha are allowed to request it.

**CaptchaCustomKey** (string, no default)
`custom` only. CSS class of the captcha div (hCaptcha: `h-captcha`).

**CaptchaCustomResponse** (string, no default)
`custom` only. Name of the form field holding the captcha answer (hCaptcha: `h-captcha-response`).

**CaptchaCustomValidateBody** (string, default `""`)
`custom` only. How the answer is sent to the validation URL: `form` (or empty) for a form POST of `secret` and `response`, or `json` for a JSON body. Any other value fails startup.

Example: [Cap Standalone](https://capjs.js.org/) as a `custom` provider:

```yaml
captchaCustomJsUrl: https://<instance>/assets/widget.js
captchaCustomKey: cap
captchaCustomResponse: cap-token
captchaCustomValidateBody: json
captchaCustomValidateUrl: https://<instance>/<site_key>/siteverify
captchaGateSecret: FIXME
captchaProvider: custom
captchaSecretKey: FIXME
captchaSiteKey: FIXME
captchaEnabled: true
```

**CaptchaCustomValidateUrl** (string, no default)
`custom` only. URL that validates the answer (hCaptcha: `https://api.hcaptcha.com/siteverify`).

**captchaEnabled** (bool, default `false`)
This middleware sets up the captcha provider and shares it as `captchaInstanceName`. Required to serve captchas; `captchaProvider` alone is not enough.

**captchaEnterpriseAction** (string, default `""`)
`recaptcha-enterprise` only. Expected action name. Required for `score` keys, optional for `checkbox` keys.

**captchaEnterpriseApiKey** (string, no default)
`recaptcha-enterprise` only. Google Cloud API key. Required.

**captchaEnterpriseKeyType** (string, no default)
`recaptcha-enterprise` only. `checkbox` or `score`. Required.

**captchaEnterpriseMinScore** (string, default `""`)
`recaptcha-enterprise` only. Minimum score to pass, greater than `0` and up to `1` (e.g. `"0.5"`). Required for `score` keys, ignored for `checkbox` keys.

**captchaEnterpriseProjectId** (string, no default)
`recaptcha-enterprise` only. Google Cloud project id. Required.

**CaptchaFilePath** (string, default `/captcha.html`)
Path to the captcha page template. Content-Type is inferred from the extension.

A custom template must put this hidden field inside its challenge form:

```html
<input type="hidden" name="crowdsec_captcha_challenge" value="v1">
```

The plugin uses it to recognise a leftover challenge form. Example: the visitor has the captcha open in two tabs, solves it in one, then submits the other. With the field, that second POST is redirected and never reaches your application. Without it, the captcha still works, but the second POST is forwarded to the backend (a route that only accepts GET answers 405). The provider's response field (`g-recaptcha-response`, `h-captcha-response`, ...) is not used for this, because your application's own forms may embed the same widget. When the loaded template does not contain the field, the plugin logs `crowdsec captcha template missing challenge marker` at startup.

**CaptchaGateBindIp** (bool, default `true`)
Tie a solved captcha to the visitor's IP. When `false`, the cookie alone is enough, even if the visitor's IP changes.

**captchaGateSecret** (string, no default)
Secret used to sign the cookie that remembers a solved captcha. Required when captcha is enabled. Use a long random value; it is not the provider's secret key.

**CaptchaGracePeriodSeconds** (int64, default `86400` / 24 hours)
How long a solved captcha is valid. After that, the visitor is challenged again if CrowdSec still has a decision for them.

**CaptchaInstanceName** (string, default the middleware name)
Name under which the captcha provider is shared, or which one to use. See [Middleware Architecture](#middleware-architecture).

**CaptchaProvider** (string, no default)
`hcaptcha`, `recaptcha`, `recaptcha-enterprise`, `turnstile`, `eucaptcha`, or `custom`.

**captchaSecretKey** (string, no default)
Secret key from the captcha provider. Required for every provider except `recaptcha-enterprise`.

**captchaSiteKey** (string, no default)
Site key from the captcha provider.

**CaptchaSiteverifyHTTPTimeoutSeconds** (int64, default `10`)
Timeout in seconds when validating a captcha with the provider. Must be at least `1`.

**AppsecBodyLimit** (int64, default `10485760` / 10 MB)
Send at most this many bytes of the request body to AppSec. `0` means no limit: the whole body is sent. Only POST, PUT, PATCH, and DELETE bodies are sent. `/crowdsec-internal/challenge/submit` must reach AppSec with the full form. The default 10MB is enough. A smaller positive limit cuts the proof short.

**appsecEnabled** (bool, default `false`)
This middleware connects to AppSec and shares the connection as `appsecInstanceName`. AppSec checks every request that passed the decision check, whatever the LAPI mode.

**AppsecHost** (string, default `"crowdsec:7422"`)
AppSec host and port.

**AppsecHttpTimeoutSeconds** (int64, default `10`)
Timeout in seconds when contacting AppSec. Must be at least `1`. For example, `1` with `bouncerAppsecFailureAction: passthrough` lets requests through after one second if AppSec hangs.

**AppsecInstanceName** (string, default the middleware name)
Name under which the AppSec connection is shared, or which one to use. See [Middleware Architecture](#middleware-architecture).

**AppsecKey** (string, default `""`)
AppSec API key. Defaults to `lapiKey`.

**AppsecPath** (string, default `"/"`)
Path appended to `appsecHost`.

**AppsecScheme** (string, default `""`)
`http` or `https`. Defaults to `lapiScheme`.

**AppsecTLSCertificateAuthority** (string, default `""`)
PEM CA that signed AppSec's certificate. Empty uses the system trust store.

**AppsecTLSClientCertificate** (string, default `""`)
PEM client certificate presented to AppSec. Used with `appsecTlsClientKey`.

**AppsecTLSClientKey** (string, default `""`)
PEM client private key presented to AppSec.

**AppsecTLSInsecureVerify** (bool, default `false`)
Do not verify AppSec's certificate. Not for production.

**BouncerActionRules** ([]object, default `[]`)
Rules that, for matching requests, skip checks or force a ban or captcha. Each rule has a unique `name` (no `:`), conditions, and an `action` list.

- Conditions (all optional, all must match): `method`, `path`, `host`, `headers`, `cookies`. Values are regular expressions matched anywhere in the value, so anchor them (`^/health$`). `method` accepts a leading `!` to negate (`!POST`). An empty header or cookie pattern means "is present". A rule must have at least one condition.
- Actions: `bypass` (skip LAPI and AppSec), `bypassLapi`, `bypassAppsec`, `bypassCaptcha`, `captcha`, `ban`. `ban` must be the only action of its rule. `captcha` and `bypassCaptcha` cannot share a rule.
- Every matching rule applies. A `ban` applies immediately. A `captcha` is shown unless CrowdSec bans the client anyway.
- A `bypass`, `bypassLapi` or `bypassAppsec` rule with a `path` only skips checks when the path can be read one way. If the request path has percent-encoding (`%2F`, `%20`...), `;`, `\`, `*`, or `.`, `..` or empty segments, the rule still applies its `captcha` but skips nothing. Some backends read such paths differently: Java servers read `/health/..;/admin` as `/admin`. Anchoring the pattern does not prevent this; this check does.
- `bypass*` rules never skip AppSec under `/crowdsec-internal/challenge/` (see bot detection above).
- `bypassCaptcha` skips no check. Where a captcha would be served, the request goes through; bans still apply. It wins over a `captcha` action of another matching rule. Its `path` is matched as written, without the check of the previous point. See [Keep captchas off API routes](#keep-captchas-off-api-routes) for where it applies and where it does not.

```yaml
bouncerActionRules:
  - name: healthcheck
    path: "^/health$"
    action: [bypass]
  - name: no-waf-for-uploads
    method: "^POST$"
    path: "^/upload/"
    action: [bypassAppsec]
  - name: internal-host
    host: "^internal\\.example\\.com$"
    action: [bypass]
  - name: captcha-some-countries
    headers:
      CF-IPCountry: "^(CN|RU|KP)$"
    action: [captcha]
  - name: api-no-captcha
    path: "^/api/"
    action: [bypassCaptcha]
```

**BouncerAppsecFailureAction** (string, default `ban`)
What to do when AppSec cannot give an answer (unreachable, error, or request body cannot be read): `ban`, `passthrough`, or `captcha`. See [Choose what happens when CrowdSec is down](#choose-what-happens-when-crowdsec-is-down).

**BouncerClientTrustedIPs** ([]string, default `[]`)
Client IPs or ranges that skip all checks, AppSec included (LAN, VPN).

**BouncerDecisionScopeHeaders** (map[string]string, default `{}`)
Maps a CrowdSec scope (country, AS, or any custom one) to the request header holding its value. See [Decisions](#decisions).

**BouncerEnabled** (bool, default `false`)
This middleware checks the requests of its router. When `false`, every request is let through (connections this middleware owns are still shared with others).

**BouncerForwardedHeadersCustomName** (string, default `"X-Forwarded-For"`)
Header holding the real client IP. Only read when the connection comes from an IP in `bouncerForwardedHeadersTrustedIps`. For `X-Forwarded-For`, trusted proxy IPs are skipped from right to left and the first other address is used. Use `X-Real-Ip` only if your front proxy (e.g. nginx or HAProxy) sets it: Traefik fills it in with the connecting IP when missing, so behind Cloudflare it would hold Cloudflare's address. Behind Cloudflare, use `CF-Connecting-IP`.

**BouncerForwardedHeadersInsecure** (bool, default `false`)
Trust the header from any connection, as a single address. Only safe when Traefik's entrypoint already restricts forwarded headers with `forwardedHeaders.trustedIPs`. Otherwise any visitor can choose the IP the plugin checks.

**BouncerForwardedHeadersTrustedIPs** ([]string, default `[]`)
IPs or ranges of the proxies in front of Traefik (for example Cloudflare's ranges). The forwarded header is only used when the connection comes from one of them; when empty, the connecting IP is used. Do not use a catch-all such as `0.0.0.0/0`: every address in the header is then treated as a proxy and the plugin silently falls back to the connecting IP. On a private network you can list private ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), as long as real clients are not in them.

**BouncerLapiFailureAction** (string, default `ban`)
What to do when LAPI cannot give an answer: `ban`, `passthrough`, or `captcha`. In `live` and `none`, this also applies when a country, AS, or other header-scope lookup fails. See [Choose what happens when CrowdSec is down](#choose-what-happens-when-crowdsec-is-down).

**BouncerOriginBasedDecisionRemap** (map[string]map[string]string, default `{}`)
Turn bans or captchas from specific origins into a captcha or a pass on this router. See [Show a community ban as a captcha](#show-a-community-ban-as-a-captcha).

**BouncerRedisUnreachableBlock** (bool, default `true`)
When Redis cannot be reached, ban (`true`) or let the request through (`false`).

**BouncerRemediationHeadersCustomName** (string, default `""`)
Response header that tells why a request was blocked or challenged. Empty disables it. See [See the verdict in access logs](#see-the-verdict-in-access-logs).

**BouncerRemediationStatusCode** (int, default `403`)
HTTP status for a ban from the LAPI, a failure action, or an action rule. It does not set the status of an AppSec ban. An AppSec ban is answered with the `http_status` of the AppSec response when it is between 200 and 599. CrowdSec sets that value to 403 unless `user_blocked_http_code` or [SetReturnCode()](https://docs.crowdsec.net/docs/appsec/hooks/#on_match) changes it, and to 429 for a `RateLimit()` block (CrowdSec 1.8.2+). To change the status of AppSec bans, set `user_blocked_http_code` in the CrowdSec appsec-config. This value applies only when the AppSec response has no valid `http_status`. A 204 or 304 status is sent without the ban page.

**BouncerTraceHeadersCustomName** (string, default `""`)
Request header copied into the ban page as `{{ .TraceID }}`. See [Put a request id on the ban page](#put-a-request-id-on-the-ban-page).

**LapiCapiMachineID** (string, no default)
`alone` only. CAPI login.

**LapiCapiPassword** (string, no default)
`alone` only. CAPI password.

**LapiCapiScenarios** ([]string, no default)
`alone` only. CAPI scenarios.

**LapiDefaultDecisionSeconds** (int64, default `60`)
`live` only. How long a LAPI answer is cached, at most.

**lapiEnabled** (bool, default `false`)
This middleware connects to LAPI and shares the connection as `lapiInstanceName`.

**LapiHost** (string, default `"crowdsec:8080"`)
LAPI host and port.

**LapiHttpTimeoutSeconds** (int64, default `10`)
Timeout in seconds when contacting LAPI. Must be at least `1`.

**LapiInstanceName** (string, default the middleware name)
Name under which the LAPI connection is shared, or which one to use. See [Middleware Architecture](#middleware-architecture).

**LapiKey** (string, default `""`)
Bouncer API key for LAPI.

**LapiMetricsUpdateIntervalSeconds** (int64, default `600`)
Seconds between metrics reports to LAPI. `0` disables metrics. See [LAPI metrics reporting](#lapi-metrics-reporting).

**LapiMode** (string, default `live`)
`stream`, `live`, `none`, or `alone`. See [LAPI modes](#lapi-modes).

**LapiPath** (string, default `"/"`)
Path appended to `lapiHost`. Ignored in `alone`.

**LapiRedisDatabase** (string, default `""`)
Redis database.

**LapiRedisEnabled** (bool, default `false`)
Use Redis instead of memory for the cache.

**LapiRedisHost** (string, default `"redis:6379"`)
Redis primary, `host:port`.

**LapiRedisPassword** (string, default `""`)
Redis password.

**LapiRedisReadHosts** ([]string, default `[]`)
Redis replicas for reads, used in turn. Defaults to `lapiRedisHost`. Reads do not fall back to the primary, so an outage of the replicas blocks requests (see `bouncerRedisUnreachableBlock`) even if the primary is up.

**LapiScheme** (string, default `http`)
`http` or `https`.

**LapiStreamScopes** ([]string, default empty)
Extra decision scopes to download in `stream` (`country`, `as`, …). IP and range decisions are always included. Set it on the middleware that connects to LAPI.

**LapiTLSCertificateAuthority** (string, default `""`)
PEM CA that signed LAPI's certificate. Empty uses the system trust store.

**LapiTLSClientCertificate** (string, default `""`)
PEM client certificate of the bouncer.

**LapiTLSClientKey** (string, default `""`)
PEM client private key of the bouncer.

**LapiTLSInsecureVerify** (bool, default `false`)
Do not verify LAPI's certificate. Not for production.

**LapiUpdateIntervalSeconds** (int64, default `60`)
Seconds between decision refreshes in `stream`. Fixed to `7200` in `alone`.

**LapiUpdateMaxFailure** (int64, default `0`)
`stream` and `alone` only. Number of failed refreshes tolerated before `bouncerLapiFailureAction` applies to clients without a known decision. `0` reacts on the first failure; `-1` never. Known decisions keep applying. In `live` and `none` it has no effect: `bouncerLapiFailureAction` applies on the first failed lookup. To let traffic through while LAPI is down there, use `bouncerLapiFailureAction: passthrough`. See [Choose what happens when CrowdSec is down](#choose-what-happens-when-crowdsec-is-down).

**LogFilePath** (string, default `""`)
Write logs to this file instead of stdout/stderr. Must be writable by Traefik.

**LogFormat** (string, default `common`)
`common` (text) or `json`.

**LogLevel** (string, default `INFO`)
`TRACE`, `DEBUG`, `INFO`, `WARN`, or `ERROR`. `TRACE` logs every request; `DEBUG` logs startup, refreshes, and errors.

**ReclaimGraceSeconds** (int64, default `30`)
How long a LAPI or AppSec connection stays open after no middleware uses it, so a Traefik config reload can reuse it instead of reconnecting. `0` closes it immediately. Only the first value loaded in the Traefik process applies.

### Configuration

The Traefik static configuration declares the plugin, and the dynamic configuration uses it in a middleware.

> You don't need to copy all these settings, only the ones you want to use.
> See the examples for advanced usage.

```yaml
# Static configuration — download a release from the Traefik plugin catalog.
# Pick a tag from https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/releases

experimental:
  plugins:
    bouncer:
      moduleName: github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin
      version: vX.Y.Z
```

```yaml
# Static configuration — or load the sources from disk as a local plugin.
# Copy or bind-mount sources to ./plugins-local/src/github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin
# relative to the Traefik working directory (see Local Mode below).

experimental:
  localPlugins:
    bouncer:
      moduleName: github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin
```

Both load the plugin through Yaegi. For production, compile it into Traefik instead (see the warning at the top).

If you also load the original plugin (`github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin`) as `bouncer`, register this one under another name, for example `crowdsec`, and use `plugin.crowdsec` in the dynamic configuration. The examples in this repository use `bouncer`.

```yaml
# Simplified dynamic configuration

http:
  routers:
    my-router:
      rule: host(`whoami.localhost`)
      service: service-foo
      entryPoints:
        - web
      middlewares:
        - crowdsec

  services:
    service-foo:
      loadBalancer:
        servers:
          - url: http://127.0.0.1:5000

  middlewares:
    crowdsec:
      plugin:
        bouncer:
          bouncerEnabled: true
          lapiEnabled: true
          lapiHost: crowdsec:8080
          lapiKey: privateKey-foo
          lapiMode: stream
          logLevel: DEBUG
```

```yaml
# Full dynamic configuration

http:
  routers:
    my-router:
      rule: host(`whoami.localhost`)
      service: service-foo
      entryPoints:
        - web
      middlewares:
        - crowdsec

  services:
    service-foo:
      loadBalancer:
        servers:
          - url: http://127.0.0.1:5000

  middlewares:
    crowdsec:
      plugin:
        bouncer:
          appsecBodyLimit: 10485760
          appsecEnabled: false
          appsecHost: crowdsec:7422
          appsecHttpTimeoutSeconds: 1
          appsecInstanceName: ""
          appsecPath: "/"
          appsecScheme: ""
          bouncerAppsecFailureAction: passthrough
          bouncerBanFilePath: /ban.html
          captchaFilePath: /captcha.html
          captchaGateSecret: FIXME
          captchaGracePeriodSeconds: 86400
          captchaProvider: hcaptcha
          captchaSecretKey: FIXME
          captchaSiteKey: FIXME
          captchaSiteverifyHttpTimeoutSeconds: 10
          bouncerClientTrustedIps:
            - 192.168.1.0/24
          bouncerActionRules:
            - name: decision-ban
              headers:
                X-Crowdsec-Decision: "^b$"
              action: [ban]
            - name: decision-captcha
              headers:
                X-Crowdsec-Decision: "^c$"
              action: [captcha]
          bouncerDecisionScopeHeaders: {}
            # Country: X-IPCountry    # key Country (any case) → ISO country matcher (CDN or geoenrich)
            # AS: CF-ASN             # key AS (any case) → ASN matcher
            # username: X-User       # any other key → trimmed exact match
          bouncerEnabled: true
          bouncerForwardedHeadersCustomName: X-Custom-Header
          bouncerForwardedHeadersTrustedIps:
            - 10.0.10.23/32
            - 10.0.20.0/24
          bouncerLapiFailureAction: ban
          bouncerOriginBasedDecisionRemap:
            CAPI:
              ban: captcha
            lists:firehol_level1:
              ban: captcha
          bouncerRedisUnreachableBlock: true
          bouncerRemediationHeadersCustomName: cs-remediation
          bouncerRemediationStatusCode: 403
          bouncerTraceHeadersCustomName: X-Request-ID
          captchaEnabled: true
          lapiCapiMachineId: login
          lapiCapiPassword: password
          lapiCapiScenarios:
            - crowdsecurity/http-path-traversal-probing
            - crowdsecurity/http-xss-probing
            - crowdsecurity/http-generic-bf
          lapiDefaultDecisionSeconds: 60
          lapiEnabled: true
          lapiHost: crowdsec:8080
          lapiHttpTimeoutSeconds: 10
          lapiInstanceName: ""
          lapiKey: privateKey-foo
          lapiMetricsUpdateIntervalSeconds: 600
          lapiMode: live
          lapiPath: "/"
          lapiRedisDatabase: "5"
          lapiRedisEnabled: false
          lapiRedisHost: "redis-primary:6379"
          lapiRedisPassword: password
          lapiRedisReadHosts:
            - "redis-replica-1:6379"
            - "redis-replica-2:6379"
          lapiScheme: http
          lapiStreamScopes: []
          lapiTlsCertificateAuthority: |-
            -----BEGIN CERTIFICATE-----
            MIIEBzCCAu+gAwIBAgICEAAwDQYJKoZIhvcNAQELBQAwgZQxCzAJBgNVBAYTAlVT
            ...
            Q0veeNzBQXg1f/JxfeA39IDIX1kiCf71tGlT
            -----END CERTIFICATE-----
          lapiTlsClientCertificate: |-
            -----BEGIN CERTIFICATE-----
            MIIEHjCCAwagAwIBAgIUOBTs1eqkaAUcPplztUr2xRapvNAwDQYJKoZIhvcNAQEL
            ...
            RaXAnYYUVRblS1jmePemh388hFxbmrpG2pITx8B5FMULqHoj11o2Rl0gSV6tHIHz
            N2U=
            -----END CERTIFICATE-----
          lapiTlsClientKey: |-
            -----BEGIN RSA PRIVATE KEY-----
            MIIEogIBAAKCAQEAtYQnbJqifH+ZymePylDxGGLIuxzcAUU4/ajNj+qRAdI/Ux3d
            ...
            ic5cDRo6/VD3CS3MYzyBcibaGaV34nr0G/pI+KEqkYChzk/PZRA=
            -----END RSA PRIVATE KEY-----
          lapiTlsInsecureVerify: false
          lapiUpdateIntervalSeconds: 60
          lapiUpdateMaxFailure: 0
          logFilePath: ""
          logFormat: common
          logLevel: DEBUG
          reclaimGraceSeconds: 30
```

#### Fill variable with value of file

These settings accept either the value itself or, with the `File` variant, a path to a file Traefik can read. When both are set, the file wins.

| Content | File |
| ------- | ---- |
| `lapiKey` | `lapiKeyFile` |
| `lapiTlsCertificateAuthority` | `lapiTlsCertificateAuthorityFile` |
| `lapiTlsClientCertificate` | `lapiTlsClientCertificateFile` |
| `lapiTlsClientKey` | `lapiTlsClientKeyFile` |
| `lapiCapiMachineId` | `lapiCapiMachineIdFile` |
| `lapiCapiPassword` | `lapiCapiPasswordFile` |
| `lapiRedisPassword` | `lapiRedisPasswordFile` |
| `appsecKey` | `appsecKeyFile` |
| `appsecTlsCertificateAuthority` | `appsecTlsCertificateAuthorityFile` |
| `appsecTlsClientCertificate` | `appsecTlsClientCertificateFile` |
| `appsecTlsClientKey` | `appsecTlsClientKeyFile` |
| `captchaSiteKey` | `captchaSiteKeyFile` |
| `captchaSecretKey` | `captchaSecretKeyFile` |
| `captchaEnterpriseApiKey` | `captchaEnterpriseApiKeyFile` |
| `captchaGateSecret` | `captchaGateSecretFile` |

#### Authenticate with LAPI

You can authenticate to LAPI either with `lapiKey` or with client certificates. Both options are described below.

#### Generate LAPI KEY

Generate a bouncer API key for LAPI, as described in the [CrowdSec documentation](https://docs.crowdsec.net/docs/user_guides/lapi_mgmt):

```bash
docker compose -f docker-compose-local.yml up -d crowdsec
docker exec crowdsec cscli bouncers add crowdsecBouncer
```

Set this key where `FIXME-LAPI-KEY` appears in `docker-compose.yml`:

```yaml
..
whoami:
  labels:
    - "traefik.http.middlewares.crowdsec.plugin.bouncer.lapiEnabled=true"
    - "traefik.http.middlewares.crowdsec.plugin.bouncer.lapiKey=FIXME-LAPI-KEY"
    - "traefik.http.middlewares.crowdsec.plugin.bouncer.lapiScheme=http"
    - "traefik.http.middlewares.crowdsec.plugin.bouncer.lapiHost=crowdsec:8080"
..
crowdsec:
  environment:
    BOUNCER_KEY_TRAEFIK: FIXME-LAPI-KEY
```

> CrowdSec accepts any string as a key, so `FIXME-LAPI-KEY` would work, but use a long random value in practice.

Then start all the containers:

```bash
docker compose up -d
```

#### Use certificates to authenticate with CrowdSec

See `examples/tls-auth` for client-certificate authentication with LAPI. In that case, LAPI must be reached over HTTPS.

The script `examples/tls-auth/gencerts.sh` generates the certificates; run it from the directory that holds the PKI input files.

#### Use HTTPS to communicate with the LAPI

Set `lapiScheme` to `https`. The plugin then verifies CrowdSec's server certificate in one of three ways:

- **Publicly trusted certificate** (e.g. Let's Encrypt behind a reverse proxy): leave `lapiTlsCertificateAuthority` empty and `lapiTlsInsecureVerify` `false`. The system trust store is used (the `traefik` image ships `ca-certificates`).
- **Private or self-signed CA**: set `lapiTlsCertificateAuthority` (or `lapiTlsCertificateAuthorityFile`) to the PEM CA that signed CrowdSec's certificate.
- **No verification** (not for production): set `lapiTlsInsecureVerify` to `true`.

CrowdSec must be listening on HTTPS. See the [tls-auth example](examples/tls-auth/README.md) or the [CrowdSec documentation](https://docs.crowdsec.net/docs/local_api/tls_auth/).

#### Use HTTPS to communicate with the Appsec

Set `appsecScheme` to `https` (if left empty, it follows `lapiScheme`). AppSec uses its own `appsecTls…` settings, with the same three options as LAPI: system trust store, a private CA in `appsecTlsCertificateAuthority`, or `appsecTlsInsecureVerify: true`.

To present a client certificate, set `appsecTlsClientCertificate` and `appsecTlsClientKey` (or their `File` variants). CrowdSec must be configured to accept it.

#### Manually add an IP to the blocklist (for testing purposes)

```bash
docker compose up -d crowdsec
docker exec crowdsec cscli decisions add --ip 10.0.0.10 -d 10m # this will be effective 10min
docker exec crowdsec cscli decisions remove --ip 10.0.0.10
docker exec crowdsec cscli decisions add --ip 10.0.0.10 -d 10m -t captcha # this will return a captcha challenge
docker exec crowdsec cscli decisions remove --ip 10.0.0.10 -t captcha
```

### Testing

Mock end-to-end tests (Traefik binary and a mock LAPI, no CrowdSec):

```bash
make e2e_mock
```

Real-stack end-to-end tests (Traefik and CrowdSec in Docker, with Pester):

```bash
./tests/e2e/real/Test-Integration.ps1
# or
make e2e_pester
```

### Examples

1. Behind another proxy service (ex: Cloudflare) — [examples/behind-proxy](examples/behind-proxy/README.md)
2. With Redis as an external shared cache — [examples/redis-cache](examples/redis-cache/README.md)
3. Using Trusted IP (ex: LAN or VPN) that won't get filtered by CrowdSec — [examples/trusted-ips](examples/trusted-ips/README.md)
4. Using CrowdSec and Traefik installed as binary in a single VM — [examples/binary-vm](examples/binary-vm/README.md)
5. Using HTTPS communication and TLS authentication with CrowdSec — [examples/tls-auth](examples/tls-auth/README.md)
6. Using CrowdSec and Traefik in Kubernetes — [examples/kubernetes](examples/kubernetes/README.md)
7. Using Traefik in standalone mode without CrowdSec — [examples/standalone-mode](examples/standalone-mode/README.md)
8. Using Traefik with AppSec enabled — [examples/appsec-enabled](examples/appsec-enabled/README.md)
9. Using Traefik with captcha remediation — [examples/captcha](examples/captcha/README.md)
10. Using Traefik with a custom ban HTML page — [examples/custom-ban-page](examples/custom-ban-page/README.md)
11. Using Traefik with a custom Wicketkeeper captcha — [examples/custom-captcha](examples/custom-captcha/README.md)
12. Using a geoenrich plugin for CrowdSec Country decisions — [examples/geoenrich-decisions](examples/geoenrich-decisions/README.md)

### Local Mode

Traefik's local plugin mode loads a plugin from disk instead of the plugin catalog.
The Traefik static configuration declares the module name (see [Configuration](#configuration)), and the sources go in a `./plugins-local` directory inside the working directory of the Traefik process:

```
./plugins-local/
    └── src
        └── github.com
            └── david-garcia-garcia
                └── crowdsec-bouncer-traefik-plugin
                    ├── plugin.go
                    ├── go.mod
                    ├── LICENSE
                    ├── Makefile
                    ├── README.md
                    └── vendor/*
```

For local development, `docker-compose.local.yml` reproduces this layout. Generate and set your LAPI key first (see [Generate LAPI KEY](#generate-lapi-key)), then run:

```bash
docker compose -f docker-compose.local.yml up -d
```

Equivalent to

```bash
make run_local
```
