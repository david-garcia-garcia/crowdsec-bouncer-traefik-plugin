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
- **Captcha passes stored on the visitor.** A solved captcha is remembered with a signed cookie on that browser (optionally tied to its IP). The original plugin whitelisted the IP on the server, so one solve let in every browser behind that address, and multi-instance setups needed Redis to share it.
- **No Redis needed.** The recommended setup keeps decisions in memory. Redis is only useful for the `live` LAPI mode with several Traefik replicas.
- **Per-router settings.** Each router keeps its own status code, captcha, trusted IPs, behavior when CrowdSec is down, and can soften specific blocklists (for example, show a captcha instead of a ban for community-list hits). The original plugin shared one set of settings across every CrowdSec middleware in Traefik.
- **Several CrowdSec engines** in one Traefik, each with its own API key, or several routers sharing one engine. See [Middleware Architecture](#middleware-architecture).
- **Config reloads apply.** Changing the LAPI host, key, mode, interval, or any other setting takes effect on a Traefik configuration reload. The original plugin kept the first values until Traefik restarted.
- **IP, IP range, country, ASN, and custom scopes.** The original plugin matched the client IP only.
- **AppSec independent of the LAPI mode.** A router can run the WAF, the decision lookup, or both.
- **Permanent rules with `bouncerActionRules`.** Ban, captcha, or skip checks for requests matching a path, host, method, header, or cookie, without any CrowdSec decision. For example, always show a captcha to a whole country or region by matching a country header such as `CF-IPCountry`. See [BouncerActionRules](#variables).

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
| `ban`       | A ban page (or an empty body) with status `bouncerRemediationStatusCode` (default 403). |
| `captcha`   | A captcha page. Once solved, the visitor is redirected back to the page they asked for and is not challenged again for `captchaGracePeriodSeconds` (default 24 hours). See [examples/captcha](examples/captcha/README.md). |

Captcha providers:

- [hCaptcha](https://www.hcaptcha.com/) (`hcaptcha`)
- [reCAPTCHA](https://www.google.com/recaptcha/about/) (`recaptcha`)
- [reCAPTCHA Enterprise](https://cloud.google.com/recaptcha/docs/introduction) (`recaptcha-enterprise`)
- [Turnstile](https://www.cloudflare.com/products/turnstile/) (`turnstile`)
- [EU CAPTCHA](https://eu-captcha.eu/) (`eucaptcha`)
- Any other widget, for example [Wicketkeeper](https://github.com/a-ve/wicketkeeper) (`custom`)

To serve captchas, set `captchaEnabled: true` together with the `captcha*` settings. Setting only `captchaProvider` is not enough.

## AppSec

This plugin supports [AppSec](https://doc.crowdsec.net/docs/next/appsec/intro/), CrowdSec's WAF, which offers:

- Low-effort virtual patching.
- Support for your existing ModSecurity rules.
- Classic WAF protection combined with CrowdSec's behavior detection.

AppSec requires CrowdSec 1.6.0 or later.

**Bot detection (CrowdSec 1.8+).** CrowdSec can answer a suspicious request with a JavaScript challenge page instead of a ban. This works out of the box once AppSec is enabled. The challenge page calls back to URLs under `/crowdsec-internal/challenge/`, and those calls must go through this middleware so CrowdSec can verify them. If the middleware already covers every path of the host, you are done. If it only covers some paths (for example `/api`), add a router for ``PathPrefix(`/crowdsec-internal/challenge`)`` with the same middleware. See [CrowdSec bot detection](https://docs.crowdsec.net/docs/next/appsec/bot_detection/intro.md).

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

Right after Traefik starts or reloads, a connection can take a moment to become available. Until it does, requests get a **503** (`bouncerStartupBlock: true`, the default) or the configured failure action (`bouncerStartupBlock: false`).

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
| `ban:unparseable-request` | The client IP could not be determined. |
| `ban:appsec` | Blocked by AppSec. |
| `ban:appsec-challenge-empty` | AppSec asked for a bot challenge but sent no page, so a ban was served instead. |
| `ban:appsec-failure` | AppSec was unreachable, and the failure action is `ban`. |
| `ban:captcha-downgrade` | A captcha was due, but this router has no captcha configured, so a ban was served. |
| `captcha:rules` | Captcha from a `bouncerActionRules` rule. |
| `captcha:lapi` / `captcha:lapi:<origin>` | Captcha from a CrowdSec decision. |
| `captcha:lapi-failure` | LAPI was unreachable, and the failure action is `captcha`. |
| `captcha:stream-unhealthy` | Decisions could not be refreshed for too long, and the failure action is `captcha`. |
| `captcha:appsec-failure` | AppSec was unreachable, and the failure action is `captcha`. |
| `captcha:appsec` | AppSec asked for a captcha. |
| `captcha:challenge` | AppSec served a bot-detection challenge. |
| `captcha:solved` | The visitor just solved the captcha and is being redirected back. |
| `error:client-disconnected` | The client disconnected while AppSec was reading the request body. Not a ban. |
| `<action>:appsec` | Any other action returned by AppSec. |

Requests that are let through get no header.

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

In `stream` and `alone` LAPI modes, the plugin keeps using the decisions it already has when LAPI is down. The failure action only applies to clients without a known decision, after `lapiUpdateMaxFailure` failed refreshes.

Right after startup or a reload, `bouncerStartupBlock` applies instead: see [Middleware Architecture](#middleware-architecture).

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
Send at most this many bytes of the request body to AppSec. `0` means no limit. Only POST, PUT, PATCH, and DELETE bodies are sent.

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
- Actions: `bypass` (skip LAPI and AppSec), `bypassLapi`, `bypassAppsec`, `captcha`, `ban`. `ban` must be the only action of its rule.
- Every matching rule applies. A `ban` applies immediately. A `captcha` is shown unless CrowdSec bans the client anyway.

```yaml
bouncerActionRules:
  - name: healthcheck
    path: "^/health$"
    action: [bypass]
  - name: no-waf-for-uploads
    method: "^POST$"
    path: "^/upload/"
    action: [bypassAppsec]
  - name: captcha-some-countries
    headers:
      CF-IPCountry: "^(CN|RU|KP)$"
    action: [captcha]
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
HTTP status for a ban.

**BouncerStartupBlock** (bool, default `true`)
Right after Traefik starts or reloads, until the CrowdSec connections this router uses are ready: return **503** (`true`) or apply the failure action (`false`).

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
`stream` and `alone` only. Number of failed refreshes tolerated before `bouncerLapiFailureAction` applies to clients without a known decision. `0` reacts on the first failure; `-1` never. Known decisions keep applying.

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
# Static configuration — load this tree as a local plugin.
# Copy or bind-mount sources to ./plugins-local/src/github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin
# relative to the Traefik working directory (see Local Mode below).

experimental:
  localPlugins:
    bouncer:
      moduleName: github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin
```

This fork is not published in the Traefik plugin catalog, so `experimental.plugins` with a `version` does not work. Load it as a local plugin, or compile it into Traefik.

If you also load the original plugin (`github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin`) as `bouncer`, register this one under another name, for example `experimental.localPlugins.crowdsec` and `plugin.crowdsec` in the dynamic configuration. The examples in this repository use `bouncer`.

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
          bouncerStartupBlock: true
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
