![GitHub](https://img.shields.io/github/license/david-garcia-garcia/crowdsec-bouncer-traefik-plugin)
![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/david-garcia-garcia/crowdsec-bouncer-traefik-plugin)
![GitHub tag (latest SemVer)](https://img.shields.io/github/v/tag/david-garcia-garcia/crowdsec-bouncer-traefik-plugin)
[![Build Status](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/workflows/main.yml/badge.svg)](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions)
[![Go Report Card](https://goreportcard.com/badge/github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin)](https://goreportcard.com/badge/github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin)

# Crowdsec Bouncer Traefik plugin

## What this plugin is

CrowdSec bouncer for Traefik. It authorizes, bans, or challenges requests from CrowdSec decisions: community lists, local detections, and optional AppSec.

A rewrite of [maxlerebourg/crowdsec-bouncer-traefik-plugin](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin). What changed:

- **AI-first.** OpenSpec specs, a knowledge base, and intensive test coverage, including mock and real-stack harnesses.
- **LAPI metrics.** Processed requests by address family, drops by decision origin and remediation, and an active-decisions count for `cscli metrics show bouncers`. The original plugin posts a single dropped counter.
- **reCAPTCHA Enterprise.** Checkbox and score keys (`recaptcha-enterprise`), plus classic reCAPTCHA, hCaptcha, Turnstile, and custom widgets.
- **EU CAPTCHA.** Provider `eucaptcha`.
- **Stateless Captcha Gate.** A passed challenge is now a cookie on the client that solved it, and can also be bound to that client's IP. The original plugin stores a server-side IP whitelist, so one solve covers every browser behind that address, and the pass exists only where that cache is reachable (it required redis backend to support distributed systems).
- **Zero dependency on Redis.** Captcha does not need Redis. The recommended setup is an in-memory `stream`, and the recommended deployment does not include Redis. Redis remains only for the historical `alone` and `live` modes.
- **Per-router settings.** Each router keeps its own status code, captcha, trusted IPs, failure action when LAPI or AppSec is down, and an optional remap of a decision origin (a community-list ban can be shown as captcha). The original plugin shares one cache and one set of key settings across every CrowdSec middleware in the process.
- **Several CrowdSec engines** in one Traefik, each with its own API key, or several routers on one engine. See [Middleware Architecture](#middleware-architecture).
- **Reload applies settings.** A Traefik router reload applies a new LAPI stream (host, key, mode, poll interval, scopes) and the rest of the middleware settings. The original plugin keeps the first stream, and the first values for interval, AppSec, metrics, and similar settings, until the Traefik process restarts.
- **Ip, Range, and other scopes.** Client IP, CIDR containment, and header-mapped scopes such as country and ASN. The original plugin matches the client IP only.
- **AppSec independent of LAPI mode.** A router can run the WAF, decision lookup, or both. The original `appsec` mode turns IP checks off.

> [!TIP]
>
> **Traefik Security**
>
> The basic middlewares you need to secure your Traefik ingress:
>
> 🌍 **Geoblock**: [david-garcia-garcia/traefik-geoblock](https://github.com/david-garcia-garcia/traefik-geoblock) - Block or allow requests based on IP geolocation
> 🛡️ **CrowdSec**: [david-garcia-garcia/crowdsec-bouncer-traefik-plugin](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin) - Real-time threat intelligence and automated blocking
> 🔒 **ModSecurity CRS**: [david-garcia-garcia/traefik-modsecurity](https://github.com/david-garcia-garcia/traefik-modsecurity) - Web Application Firewall with OWASP Core Rule Set
> 🚦 **Ratelimit**: [Traefik Rate Limit](https://doc.traefik.io/traefik/reference/routing-configuration/http/middlewares/ratelimit/) - Control request rates and prevent abuse

> [!WARNING]
>
> **Do not run middlewares as Yaegi plugins in production.**
>
> Traefik's catalog loads plugins with [Yaegi](https://github.com/traefik/yaegi), a Go interpreter. A middleware runs on every request, so that cost is on the hot path: memory, CPU, and observability ([Yaegi #1712](https://github.com/traefik/yaegi/pull/1712)). For real traffic, compile the middleware into the Traefik binary, for example [traefik-with-plugins](https://github.com/david-garcia-garcia/traefik-with-plugins). Discussion: [Traefik #12213](https://github.com/traefik/traefik/issues/12213).

## What CrowdSec is

<img src="https://docs.crowdsec.net/img/crowdsec_logo.png" alt="CrowdSec" height="80">

> [CrowdSec](https://www.crowdsec.net/) is an open-source and collaborative IPS (Intrusion Prevention System) and a security suite.
> We leverage local behavior analysis and crowd power to build the largest CTI network in the world.

The Crowdsec utility will provide the community blocklist which contains highly reported and validated IPs banned from the Crowdsec network.

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

This plugin is the bouncer: it asks LAPI (and optionally AppSec) on the request path. It does not ingest logs.

How one Traefik process can share a stream, or run several CrowdSec engines, is in [Middleware Architecture](#middleware-architecture).

## Decisions

A CrowdSec decision is *who* (scope) plus *what* (remediation). This plugin looks up that pair.

Decision **scopes** supported by the plugin are `Ip`, `Range` (CIDR), and any other CrowdSec scope listed in `bouncerDecisionScopeHeaders`.

`bouncerDecisionScopeHeaders` maps a CrowdSec **scope name** (the map key) to a request **header name** (the map value). The key selects how the header is interpreted, not the header name:

- `Country` (any case: `country`, `Country`): ISO 3166-1 alpha-2, case-insensitive. Cloudflare `XX` and `T1` do not match. Example headers: `CF-IPCountry`, or `X-IPCountry` from a geoenrich middleware.
- `AS` (any case: `as`, `AS`): decimal ASN. A leading `AS` / `as` on the header or the decision is ignored. Example header: `CF-ASN`.
- Any other key (`username`, `session`, …): trimmed header string, compared as-is to the decision value. The key must match the scope LAPI stored (`username` is not `user`).
- `Ip` and `Range` cannot be mapped. IP comes from the client address; Range is CIDR containment.

```yaml
bouncerDecisionScopeHeaders:
  Country: X-IPCountry
  AS: CF-ASN
  username: X-User
```

The plugin does not resolve GeoIP or invent header values. Every `bouncerDecisionScopeHeaders` scope is taken from the request as-is (CDN, reverse proxy, or a Traefik middleware such as [traefik-geoblock](https://github.com/david-garcia-garcia/traefik-geoblock)). If the client can set that header, they can change matching — use only values you trust when the header is not client-controlled. A worked chain is in [examples/geoenrich-decisions](examples/geoenrich-decisions/README.md).

## Remediation

CrowdSec remediations this plugin applies ([CrowdSec bouncers](https://docs.crowdsec.net/u/bouncers/intro)):

| Remediation | What the user gets |
| ----------- | ------------------ |
| `ban`       | Ban page (or empty body) with `RemediationStatusCode` (default 403) |
| `captcha`   | A challenge page. After they pass, they are clean for a grace period, then challenged again if CrowdSec still has a decision. See [examples/captcha](examples/captcha/README.md). |

Captcha providers:

- [hCaptcha](https://www.hcaptcha.com/)
- [reCAPTCHA](https://www.google.com/recaptcha/about/) (classic `recaptcha`: `api.js` / siteverify)
- [reCAPTCHA Enterprise](https://cloud.google.com/recaptcha/docs/introduction) (`recaptcha-enterprise`: `enterprise.js` / Cloud assessments)
- [Turnstile](https://www.cloudflare.com/products/turnstile/)
- [EU CAPTCHA](https://eu-captcha.eu/) (`eucaptcha`: `verify.js` / `POST /v1/verify`; site key and secret required)
- [custom / Wicketkeeper](https://github.com/a-ve/wicketkeeper)

## AppSec

This plugin supports [AppSec](https://doc.crowdsec.net/docs/next/appsec/intro/), including virtual patching and legacy ModSecurity rules.

Appsec feature is supported from plugin version 1.2.0 and Crowdsec 1.6.0. CrowdSec 1.8 AppSec **bot-detection** (challenge HTML, `__crowdsec_challenge` cookie, `/crowdsec-internal/challenge/*`) is supported by this plugin: enable AppSec as usual and route that path prefix through the **same** CrowdSec middleware as the protected app so the callback is not sent to origin. There is no extra plugin option. See [CrowdSec bot detection](https://docs.crowdsec.net/docs/next/appsec/bot_detection/intro.md).

The AppSec Component offers:

- Low-effort virtual patching capabilities.
- Support for your legacy ModSecurity rules.
- Combining classic WAF benefits with advanced CrowdSec features for otherwise difficult advanced behavior detection.

More information on appsec in the [Crowdsec Documentation](https://doc.crowdsec.net/docs/next/appsec/intro/).

## Modes

There are four operating modes (`lapiMode`). Sequence diagrams live in [docs/modes.md](docs/modes.md).

| Mode   | Summary |
| ------ | ------- |
| none   | Every request asks LAPI. No decision cache. Ban or captcha from that answer. |
| live   | Same as none, but caches each IP's result. |
| stream | Sync decisions from LAPI on an interval; the request path hits cache only. Recommended. |
| alone  | Like stream, but pulls the community blocklist from CAPI. No local CrowdSec. |

`stream` is recommended: decisions refresh every 60 seconds by default. The request path does not call LAPI. Usage-metrics still POST to LAPI on `lapiMetricsUpdateIntervalSeconds` unless that interval is zero or less.

`lapiMode` is how an **owned** LAPI client fetches decisions. It is not “which pieces this middleware runs.” AppSec-only is `lapiEnabled: false` plus `appsecEnabled: true`. `lapiMode: appsec` is removed.

## Middleware Architecture

One Traefik middleware object can run up to four independent pieces:

| Piece | Flag | Job |
| ----- | ---- | --- |
| LAPI client | `lapiEnabled` | Open one connection to one CrowdSec LAPI (`stream` / `live` / `none` / `alone`). Publish it under `lapiInstanceName`. |
| AppSec client | `appsecEnabled` | Open one AppSec listener. Publish it under `appsecInstanceName`. |
| Captcha client | `captchaEnabled` | Open one siteverify client, template, and gate. Publish it under `captchaInstanceName`. |
| Bouncer | `bouncerEnabled` | Serve this router: subscribe to those names, apply this route’s remediations (status, header, captcha, trusted IPs, failure action). |

`bouncerEnabled` never opens a backend. An omitted instance name is filled with this Traefik middleware name only when that piece’s owner flag is true. LAPI, AppSec, and captcha use **separate** name tables, so all three may be called `shared`. A bouncing subscriber sets `bouncerEnabled: true` and the instance name, and leaves the owner flag false so it does not Open.

**BREAKING:** Owner-read captcha settings moved from `bouncerCaptcha*` / `BouncerCaptcha*` to `captcha*` / `Captcha*`. No old-key aliases. Operators must rename labels and YAML. Leftover `bouncerCaptcha*` is dropped. A leftover pre-prefix `captchaFilePath` starts matching `CaptchaFilePath` again (the captcha stem, not an alias).

**BREAKING:** YAML that only sets `captchaProvider` no longer owns or serves captcha. Set `captchaEnabled: true` on the owner (empty `captchaInstanceName` fills to the Traefik name). `captcha` failure action requires that router’s captcha instance name after fill.

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

`New` never waits for a publisher (that deadlocks Traefik). A missing subscribed backend with `bouncerStartupBlock: true` is **503** on the request; with the flag false it uses that piece’s failure action.

### One middleware (all-in-one)

Names omitted: this Traefik name is the slot. Same shape as a single-router install.

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

### Shared stream, per-router bounce policy

One middleware owns the LAPI (and optional AppSec) stream. Other routers only bounce: they subscribe by name and keep their own policy. They do not copy host, key, mode, or poll interval.

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

A dummy owner (`enabled: false`) is optional. Use it only when no bouncing route should own the clients. Traefik still needs a router attached so `New` runs.

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

CrowdSec still identifies **one stream per LAPI key + the IP this Traefik uses to call LAPI**. Two stream owners that share that pair fight over one cursor. A second isolated decision set needs a **second LAPI key** (and usually a second host if it is another engine).

Give each owner its own instance name. Point each bouncing router at the name it should use.

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

`/app-a` and `/app-b` can sit on the same Traefik. They do not share a decision store. The same pattern works for two streams against one engine (two bouncer API keys) when you want isolated cursors.

### AppSec only

No LAPI client on this middleware. The bouncer subscribes only to AppSec.

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

`lapiStreamScopes` is opener-only extra stream scopes (`country`, `as`, …). It is not copied from `bouncerDecisionScopeHeaders`.

## Cache

The cache remembers CrowdSec remediations so this plugin does not have to ask LAPI on every request.

- **`live`**: stores each client result (banned, captcha, or clean) for `DefaultDecisionSeconds`. This is the mode where a shared Redis cache is useful: several Traefik replicas can reuse the same LAPI answers.
- **`stream` / `alone`**: stores the decision list locally. Prefer the in-memory store. Redis adds a network hop for a set you already sync on an interval.
- **`none`**: no decision cache to share.

Captcha grace does not use this cache. After a passed challenge, the plugin sets a signed cookie (`crowdsec_captcha_gate`), not a cache key.

## Usage

To get started, use the `docker-compose.yml` file.

You can run it with:

```bash
make run
```

### Note

> [!IMPORTANT]
> You can declare many CrowdSec middlewares in one Traefik. Each bouncing router keeps its own request policy (enabled, captcha, trusted IPs, failure actions, templates).
>
> Share one LAPI, AppSec, or captcha client by publishing a name (`lapiInstanceName` / `appsecInstanceName` / `captchaInstanceName`) and subscribing other routers to it. Interval, host, key, `lapiStreamScopes`, and captcha provider settings live on the **owner**. See [Middleware Architecture](#middleware-architecture).
>
> CrowdSec LAPI still identifies **one stream per LAPI key + the IP this Traefik uses to call LAPI**. A second isolated stream or engine needs a different key (and a different instance name). Two stream owners on the same pair fight over one cursor.

> [!WARNING]  
> **Appsec maximum body limit is defaulted to 10MB** > _Be careful when you upgrade to >1.4.x_

### Variables

**BouncerBanFilePath** (string, default `""`)
Path to the ban file. Empty disables it. Content-Type is inferred from the extension.

**CaptchaCustomChallengeUrl** (string, default `""`)
`custom` only. Origin widget challenge URL (Wicketkeeper: `http://captcha.localhost:8000/v0/challenge`). Rendered as `{{ .ChallengeURL }}`. A captcha-flagged client may request this exact path and it is passed through (banned clients are not). Empty means no challenge passthrough.

**CaptchaCustomJsUrl** (string, no default)
`custom` only. URL that loads the challenge in HTML (hCaptcha: `https://hcaptcha.com/1/api.js`). When the widget is on the protected router, a captcha-flagged client may request this exact path and it is passed through (banned clients are not).

**CaptchaCustomKey** (string, no default)
`custom` only. CSS class of the captcha div (hCaptcha: `h-captcha`).

**CaptchaCustomResponse** (string, no default)
`custom` only. POST field from `captcha.html` (hCaptcha: `h-captcha-response`).

**CaptchaCustomValidateBody** (string, default `""`)
Siteverify request encoding. After trim, exact lowercase `""` or `form` POSTs `application/x-www-form-urlencoded` `secret` and `response` (same as omit; Wicketkeeper). `json` POSTs `application/json` `{"secret","response"}`. `json` is `custom` only — a built-in plus `json` fails startup. `JSON`, `Form`, and any other token fail for every provider.

CapJS / Cap Standalone as `custom` (operator HTML stays yours; no `trycap` provider):

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
`custom` only. URL that validates the challenge (hCaptcha: `https://api.hcaptcha.com/siteverify`). Cap Standalone: `https://<instance>/<site_key>/siteverify` with `captchaCustomValidateBody: json`.

**captchaEnterpriseAction** (string, default `""`)
`recaptcha-enterprise` only. Assessment `expectedAction` and checkbox `data-action`. Required for `score`. Empty is valid for `checkbox` (omits both).

**captchaEnterpriseApiKey** (string, no default)
`recaptcha-enterprise` only. Google Cloud API key sent as `X-Goog-Api-Key`. Required when this provider is selected.

**captchaEnterpriseApiKeyFile** (string, no default)
File path for `captchaEnterpriseApiKey` (preferred over an inline key when both are set).

**captchaEnterpriseKeyType** (string, no default)
`recaptcha-enterprise` only. Expected: `checkbox` or `score`. Required when this provider is selected.

**captchaEnterpriseMinScore** (string, default `""`)
`recaptcha-enterprise` only. Minimum `riskAnalysis.score` (`0.0`–`1.0`) as a string. Required for `score` and must parse greater than `0` and at most `1`. Empty is valid for `checkbox` (score is ignored).

**captchaEnterpriseProjectId** (string, no default)
`recaptcha-enterprise` only. Google Cloud project id in the assessments URL. Required when this provider is selected.

**CaptchaFilePath** (string, default `/captcha.html`)
Path to the captcha template. Content-Type is inferred from the extension.

**CaptchaGateBindIp** (bool, default `true`)
When true, the gate cookie binds to the client IP from `GetRemoteIP`. When false, grace is cookie-only (HMAC + expiry).

**captchaGateSecret** (string, no default)
HMAC secret for the stateless captcha grace cookie (`crowdsec_captcha_gate`). Required when `captchaEnabled` is true. Not the same as `captchaSecretKey`.

**captchaGateSecretFile** (string, no default)
File path for `captchaGateSecret` (preferred over an inline secret when both are set).

**CaptchaGracePeriodSeconds** (int64, default `1800` / 30 minutes)
How long after a passed captcha before a new challenge, if the CrowdSec decision is still valid.

**CaptchaProvider** (string, no default)
Captcha validator. Expected: `hcaptcha`, `recaptcha`, `recaptcha-enterprise`, `turnstile`, `custom`, `eucaptcha`. Classic `recaptcha` stays on `api.js` and siteverify. `recaptcha-enterprise` loads `enterprise.js` and calls Cloud assessments. `eucaptcha` loads `verify.js` and POSTs JSON to EU CAPTCHA `/v1/verify`.

**captchaSecretKey** (string, no default)
Site secret key for the captcha provider. Unused for `recaptcha-enterprise` (not required). Required for `hcaptcha`, `recaptcha`, `turnstile`, `custom`, and `eucaptcha`.

**captchaSiteKey** (string, no default)
Site key for the captcha provider.

**CaptchaSiteverifyHTTPTimeoutSeconds** (int64, default `10`)
Timeout in seconds for the captcha provider siteverify client. MUST be `>= 1`. Independent of the LAPI and AppSec timeouts.

**BouncerClientTrustedIPs** ([]string, default `[]`)
Client IPs that bypass bouncer and cache checks (LAN or VPN). Trusted clients also skip AppSec.

**AppsecBodyLimit** (int64, default `10485760` / 10MB)
Send only the first N bytes to AppSec. `0` is unlimited. Only POST, PUT, PATCH, and DELETE bodies are forwarded; any other method (including a GET with a body) is sent as a headers-only GET with the real verb on `X-Crowdsec-Appsec-Verb`.

**appsecEnabled** (bool, default `false`)
Enable CrowdSec AppSec (WAF). Independent of `lapiMode`: it inspects the requests the decision check allowed, in every mode. CrowdSec 1.8 bot-detection needs this set, plus a Traefik router `PathPrefix(/crowdsec-internal/challenge)` using this same middleware.

**BouncerAppsecExcludeRegex** (string, default `""`)
RE2 pattern matched against `{host}/path` (no scheme, no port, no query). A match skips the AppSec query on the pass path. Empty after trim is off. The match is unanchored (`MatchString` reports whether the string contains any match); write `^...$` to match the whole string. Case-sensitive unless the pattern includes `(?i)`. Invalid pattern fails `New`. Host is the request `Host` with the port stripped (`net.SplitHostPort` when that succeeds; an IPv6 host with a port loses brackets). Path is the decoded URL path (`/` when empty).

**BouncerAppsecFailureAction** (string, default `ban`)
What to do when AppSec does not return a usable verdict (HTTP 500, unreachable, body read error, or unreadable HTTP/2 or HTTP/3 body on POST/PUT/PATCH). Expected: `passthrough`, `ban`, `captcha`. `ban` drops the request. `passthrough` lets 500/unreachable/body-io errors continue as allow, and sends a headers-only GET when the body cannot be buffered. `captcha` uses the subscribed published captcha client (`captchaEnabled` or a non-empty `captchaInstanceName` after owner-fill). **BREAKING:** replaces `crowdsecAppsecFailureBlock`, `crowdsecAppsecUnreachableBlock`, and `crowdsecAppsecUnreadableBodyBlock`. Operators who had those bools set to `false` MUST set `bouncerAppsecFailureAction: passthrough`.

**appsecHost** (string, default `"crowdsec:7422"`)
AppSec host and port.

**appsecHttpTimeoutSeconds** (int64, default `10`)
Timeout in seconds when contacting AppSec. MUST be `>= 1`. Independent of the LAPI and captcha siteverify timeouts. Example: `appsecHttpTimeoutSeconds: 1` with `bouncerAppsecFailureAction: passthrough` so an AppSec hang fails open after one second.

**appsecKey** (string, default value of `lapiKey`)
AppSec key for the bouncer.

**appsecPath** (string, default `"/"`)
AppSec path, appended to `appsecHost`. Must end with `/`.

**appsecScheme** (string, default value of `lapiScheme`)
Expected: `http`, `https`.

**AppsecTLSCertificateAuthority** (string, default `""`)
PEM CA used to verify AppSec's server certificate. When empty (and `appsecTlsInsecureVerify` is `false`), the host system trust store is used.

**AppsecTLSInsecureVerify** (bool, default `false`)
Disable verification of the certificate presented by AppSec.

**LapiCapiMachineID** (string, no default)
`alone` only. CAPI login.

**LapiCapiPassword** (string, no default)
`alone` only. CAPI password.

**LapiCapiScenarios** ([]string, no default)
`alone` only. CAPI scenarios.

**BouncerDecisionHeader** (string, default `""`)
Incoming request header that forces ban or captcha. Empty disables the feature (the plugin does not read `X-Crowdsec-Decision` unless you set this key). Values are exact trimmed `b` (ban) or `c` (captcha). `b` applies ban without a stream or live lookup. `c` still consults that lookup: a CrowdSec ban wins and the plugin logs WARN `ServeHTTP:forcedCaptchaSuperseded`; otherwise captcha. Any other token, including `t` and `B`, is ignored and lookup continues. Put a Traefik middleware that writes this header *before* the bouncer. Do not expose the header to the internet; any client who can set it can captcha or ban themselves. A `c` value still honors the captcha gate cookie when lookup is not ban: a visitor who already solved captcha reaches origin even while the header is still `c`. Trusted client IPs still skip the whole plugin, including this header.

**BouncerLapiExcludeRegex** (string, default `""`)
RE2 pattern matched against `{host}/path` (no scheme, no port, no query). A match skips the whole LAPI remediation path (`LookupRemediation`, `LiveLookup`, missing-LAPI failure action, and stream/alone unhealthy failure action) and continues on the pass path (AppSec may still run). Empty after trim is off. The match is unanchored; write `^...$` to match the whole string. Invalid pattern fails `New`. Same host/path rules as `bouncerAppsecExcludeRegex`. Exclude runs after trusted IPs and forced `b`; forced `c` still applies on the pass path. These strings are not part of LAPI or AppSec reclaim keys.

**BouncerLapiFailureAction** (string, default `ban`)
What to do when LAPI does not return a usable verdict (live/none HTTP or parse error, or a cache miss while stream/alone is unhealthy after `lapiUpdateMaxFailure`). Expected: `passthrough`, `ban`, `captcha`. Cache hits still apply when the stream is unhealthy. `passthrough` uses the pass path (AppSec still runs if enabled). `captcha` uses the subscribed published captcha client (`captchaEnabled` or a non-empty `captchaInstanceName` after owner-fill). **Behavior change:** in `live` and `none`, this action also covers a failed `bouncerDecisionScopeHeaders` query. Previously a LAPI that answered the IP query but errored on a header-scope query was treated as "no decision" and allowed (`DEBUG`). That is now a LAPI failure: default `ban` blocks those requests and logs `WARN`. An active ban still wins. Set `bouncerLapiFailureAction: passthrough` to keep allowing when a header-scope query fails.

**lapiHost** (string, default `"crowdsec:8080"`)
LAPI host and port.

**lapiHttpTimeoutSeconds** (int64, default `10`)
Timeout in seconds when contacting LAPI. MUST be `>= 1`. Independent of the AppSec and captcha siteverify timeouts.

**lapiKey** (string, default `""`)
LAPI key for the bouncer.

**lapiPath** (string, default `"/"`)
LAPI path, appended to `lapiHost`. Must end with `/`.

**lapiScheme** (string, default `http`)
Expected: `http`, `https`.

**LapiTLSCertificateAuthority** (string, default `""`)
PEM CA used to verify LAPI's server certificate. When empty (and `lapiTlsInsecureVerify` is `false`), the host system trust store is used.

**LapiTLSClientCertificate** (string, default `""`)
PEM client certificate of the bouncer.

**LapiTLSClientKey** (string, default `""`)
PEM client private key of the bouncer.

**LapiTLSInsecureVerify** (bool, default `false`)
Disable verification of the certificate presented by LAPI.

**LapiMode** (string, default `live`)
Expected: `none`, `live`, `stream`, `alone`, `appsec`.

**BouncerDecisionScopeHeaders** (map[string]string, default `{}`)
Maps a CrowdSec scope name (key) to a request header (value). `Country` (any case) is ISO 3166-1 alpha-2 and ignores `XX`/`T1`; `AS` (any case) is decimal digits and strips a leading `AS`; any other key is a trimmed exact match. Do not map `Ip` or `Range`. Empty disables header scopes. This plugin does not geolocate. See the `bouncerDecisionScopeHeaders` example above.

**LapiDefaultDecisionSeconds** (int64, default `60`)
`live` only. Maximum decision duration.

**BouncerEnabled** (bool, default `false`)
Enable the plugin.

**BouncerForwardedHeadersCustomName** (string, default `"X-Forwarded-For"`)
Header that holds the real client IP. Read only when the socket peer is in `bouncerForwardedHeadersTrustedIps`. That list also skips hops in the header right-to-left; the first value not in the list wins. `X-Real-Ip` is trustworthy only when the front proxy sets it. Traefik's entrypoint deletes `X-Forwarded-*` and `X-Real-Ip` from untrusted peers and only writes `X-Real-Ip` when absent, filling it with the socket peer. Cloudflare sends `CF-Connecting-IP` and `X-Forwarded-For` but not `X-Real-Ip`, so Traefik would fill in the Cloudflare edge and every visitor would be remediated as Cloudflare. Use `X-Real-Ip` with an nginx or HAProxy front that sets it.

**BouncerForwardedHeadersInsecure** (bool, default `false`)
Skip the socket-peer gate, treat the named header as a single client address with no hop walk, and default the header to `X-Real-Ip` when `bouncerForwardedHeadersCustomName` is still `X-Forwarded-For`. Safe only when the Traefik entrypoint has `forwardedHeaders.trustedIPs` set and is not running with `forwardedHeaders.insecure: true`. Otherwise any client can choose which IP this plugin bans, captchas, and caches.

**BouncerForwardedHeadersTrustedIPs** ([]string, default `[]`)
IPs of trusted proxies in front of Traefik (for example Cloudflare). The forwarded header is honored only when the connecting peer is in this list. While empty, forwarded headers are ignored and the plugin remediates the connecting address. If Traefik sits behind a load balancer or CDN, list it here or every visitor is remediated as the proxy. Without `bouncerForwardedHeadersInsecure` there is no way to trust every peer. A catch-all `0.0.0.0/0` plus `::/0` passes the peer check but then treats the header value as a trusted hop and falls back to the connecting address with no warning (peer `203.0.113.7`, `X-Real-Ip: 198.51.100.9` resolves to `203.0.113.7`). `0.0.0.0/0` is IPv4 only and `::/0` is IPv6 only. Private ranges `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` are the alternative to enumerating proxies on a private ingress: the peer must be inside a listed range and the real client must not. Verified working: pool `172.16.0.0/12`, peer `172.18.0.5`, `X-Real-Ip: 198.51.100.9` → `198.51.100.9`. Verified failure: pool `10.0.0.0/8`, peer `10.1.2.3`, `X-Real-Ip: 10.9.9.9` → `10.1.2.3`.

**LogFilePath** (string, default `""`)
File path for logs. Must be writable by Traefik. Rotation may need a Traefik restart.

**LogFormat** (string, default `common`)
`common` for text logs, `json` for structured JSON. Expected: `common`, `json`.

**LogLevel** (string, default `INFO`)
Logs go to `stdout` / `stderr`, or to a file if `LogFilePath` is set. Expected: `TRACE`, `DEBUG`, `INFO`, `WARN`, `ERROR`. `TRACE` is for per-request breadcrumbs (`ServeHTTP`, captcha check); `DEBUG` is for startup, stream ticks, and request-path failures.

**LapiMetricsUpdateIntervalSeconds** (int64, default `600`)
Seconds between metrics updates to CrowdSec. Zero or less disables collection.

**BouncerOriginBasedDecisionRemap** (map[string]map[string]string, default `{}`)
Origin-keyed remap of LAPI decision types to a weaker kind at request apply (per Traefik middleware instance). Outer key is the metrics origin (`MetricsOrigin`): `CAPI` is exact; `lists` matches every CrowdSec list; `lists:<name>` matches one list (the decision scenario). Inner key is the original LAPI type (`ban` or `captcha`). Inner value is `captcha` or `pass`. One hop on the original type: `CAPI: {ban: captcha, captcha: pass}` treats a CAPI ban as captcha and does not chain to pass. `pass` skips LAPI remediation (AppSec still runs). The DecisionStore keeps the LAPI kind. Unmapped origins and types keep the LAPI type. Invalid pairs fail configuration validation. Without a captcha provider, applied captcha still renders as ban. Two routers sharing one LAPI Client may disagree.

**LapiRedisDatabase** (string, default `""`)
Redis database selection.

**LapiRedisEnabled** (bool, default `false`)
Use Redis instead of in-memory cache.

**LapiRedisHost** (string, default `"redis:6379"`)
Redis write host (primary), `host:port`.

**LapiRedisPassword** (string, default `""`)
Redis password.

**LapiRedisReadHosts** ([]string, default `[]`)
Redis replica hosts for reads (round-robin). Falls back to `lapiRedisHost` when empty. When set, reads are not retried against the primary if replicas are unreachable. With `bouncerRedisUnreachableBlock` at its default (`true`), a replica outage blocks or delays requests even if the primary is healthy.

**BouncerRedisUnreachableBlock** (bool, default `true`)
Block the request when Redis is unreachable (adds a 1-second delay per request).

**ReclaimGraceSeconds** (int64, default `30`)
Process-wide wait after the last holder of a LAPI or AppSec client, so a Traefik reload can reuse the same incarnation. First `New` in the process sets it; later middlewares are ignored. Zero disposes as soon as the last holder ends. Not captcha cookie grace.

**BouncerRemediationHeadersCustomName** (string, default `""`)
Response header name when the plugin handles the request. Header value is `ban`, `captcha`, `solved-captcha`, or `error:client-disconnected` (client dropped the body while AppSec was buffering; not a ban). Include this header in Traefik `accessLog.fields.headers` if you want disconnects in access logs. Empty disables the header.

**BouncerRemediationStatusCode** (int, default `403`)
HTTP status for a banned user (not captcha).

**BouncerStartupBlock** (bool, default `true`)
On the request path, `true` returns **503** while any backend this bouncer subscribes to is not published yet. `false` uses that leg's failure action. `New` never waits. Ready here means the subscribed client is published, not that the first stream poll finished.

**lapiEnabled** (bool, default `false`)
This middleware owns a LAPI client (`Open` + publish). Bounce still uses `bouncerEnabled`.

**captchaEnabled** (bool, default `false`)
This middleware owns a captcha client (`Open` + publish). Bounce still uses `bouncerEnabled`. A set `captchaProvider` alone does not own captcha.

**LapiInstanceName** / **AppsecInstanceName** / **CaptchaInstanceName** (string, default Traefik name when that leg is owned)
Slot name bouncers subscribe to. LAPI, AppSec, and captcha are separate tables, so all three may be `shared`.

**LapiStreamScopes** ([]string, default empty)
Extra LAPI stream scopes (`country`, `as`, …). Omitted or empty is `ip,range` only. Opener only; not copied from `bouncerDecisionScopeHeaders`.

**BouncerTraceHeadersCustomName** (string, default `""`)
Request header whose value is injected into the ban HTML. Empty disables it.

**LapiUpdateIntervalSeconds** (int64, default `60`)
`stream` only. Interval between LAPI blacklist fetches.

**LapiUpdateMaxFailure** (int64, default `0`)
`stream` and `alone` only. How many times CrowdSec can be unreachable before traffic is blocked (`-1` never blocks).

### Configuration

For each plugin, the Traefik static configuration must define the module name (as is usual for Go packages).

The following declaration (given here in YAML) defines a plugin:

> Note that you don't need to copy all thoses settings but only the ones you want to use.  
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

A catalog `GET` of `github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin` at `v1.7.1` or `vX.Y.Z` returns 404, and plugins.traefik.io does not list forks. Do not use `experimental.plugins` plus a `version` of this module as the working install.

If the host already loads upstream `experimental.plugins.bouncer` (`github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin`), register this fork under a different alias, for example `experimental.localPlugins.crowdsec` and `plugin.crowdsec` in the dynamic YAML. In-tree examples keep alias `bouncer`.

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
          lapiMode: live
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
          captchaGracePeriodSeconds: 1800
          captchaProvider: hcaptcha
          captchaSecretKey: FIXME
          captchaSiteKey: FIXME
          captchaSiteverifyHttpTimeoutSeconds: 10
          bouncerClientTrustedIps:
            - 192.168.1.0/24
          bouncerDecisionHeader: X-Crowdsec-Decision # optional; earlier middleware writes b or c
          bouncerDecisionScopeHeaders: {}
            # Country: X-IPCountry    # key Country (any case) → ISO country matcher (CDN or geoenrich)
            # AS: CF-ASN             # key AS (any case) → ASN matcher
            # username: X-User       # any other key → trimmed exact match
          bouncerEnabled: false
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

`LapiTLSClientKey`, `LapiTLSClientCertificate`, `LapiTLSCertificateAuthority`, `AppsecTLSCertificateAuthority`, `LapiCapiMachineID`, `LapiCapiPassword`, `lapiKey`, `appsecKey`, `captchaSiteKey`, `captchaSecretKey`, `captchaEnterpriseApiKey`, `captchaGateSecret` and `LapiRedisPassword` can be provided with the content as raw or through a file path that Traefik can read.  
The file variable will be used as preference if both content and file are provided for the same variable.

Format is:

- Content: VariableName: XXX
- File : VariableNameFile: /path

#### Authenticate with LAPI

You can authenticate to the LAPI either with lapiKey or by using client certificates.  
Please see below for more details on each option.

#### Generate LAPI KEY

You can generate a crowdsec API key for the LAPI.  
You can follow the documentation here: [docs.crowdsec.net/docs/user_guides/lapi_mgmt](https://docs.crowdsec.net/docs/user_guides/lapi_mgmt)

```bash
docker compose -f docker-compose-local.yml up -d crowdsec
docker exec crowdsec cscli bouncers add crowdsecBouncer
```

This LAPI key must be set where is noted FIXME-LAPI-KEY in the docker-compose.yml

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

Note:

> Crowdsec does not require a specific format for la LAPI-key, you may use something like FIXME-LAPI-KEY but that is not recommanded for obvious reasons

You can then run all the containers:

```bash
docker compose up -d
```

#### Use certificates to authenticate with CrowdSec

You can follow the example in `examples/tls-auth` to view how to authenticate with client certificates with the LAPI.  
In that case, communications with the LAPI must go through HTTPS.

A script is available to generate certificates in `examples/tls-auth/gencerts.sh` and must be in the same directory as the inputs for the PKI creation.

#### Use HTTPS to communicate with the LAPI

Set `lapiScheme` to `https`. The plugin then validates Crowdsec's server certificate. Three options:

- **Publicly trusted certificate** (e.g. Let's Encrypt behind a reverse proxy): leave `lapiTlsCertificateAuthority` empty and `lapiTlsInsecureVerify` `false`. The plugin falls back to the host's system trust store (the `traefik` image ships `ca-certificates`).
- **Private/self-signed CA**: set `lapiTlsCertificateAuthority` (or `…File`) to the PEM-encoded CA that signed Crowdsec's server cert.
- **Skip verification entirely** (not recommended for production): set `lapiTlsInsecureVerify` to `true`.

Crowdsec must be listening in HTTPS for this to work.
Please see the [tls-auth example](examples/tls-auth/README.md) or the official documentation: [docs.crowdsec.net/docs/local_api/tls_auth/](https://docs.crowdsec.net/docs/local_api/tls_auth/)

#### Use HTTPS to communicate with the Appsec

Set `appsecScheme` to `https`. Same three options as for the LAPI, prefixed `appsecTls…` instead of `lapiTls…`: empty CA + secure verify falls back to the system trust store, a custom CA pins to your private PKI, and `appsecTlsInsecureVerify=true` skips verification altogether.

Currently AppSec does not support mTLS authentication for the AppSec Component.

#### Manually add an IP to the blocklist (for testing purposes)

```bash
docker compose up -d crowdsec
docker exec crowdsec cscli decisions add --ip 10.0.0.10 -d 10m # this will be effective 10min
docker exec crowdsec cscli decisions remove --ip 10.0.0.10
docker exec crowdsec cscli decisions add --ip 10.0.0.10 -d 10m -t captcha # this will return a captcha challenge
docker exec crowdsec cscli decisions remove --ip 10.0.0.10 -t captcha
```

### Testing

Mock e2e (Traefik binary + mock LAPI, no Crowdsec):

```bash
make e2e_mock
```

Real-stack e2e (Docker Traefik + Crowdsec, Pester):

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

Traefik also offers a developer mode that can be used for temporary testing of plugins not hosted on GitHub.
To use a plugin in local mode, the Traefik static configuration must define the module name (as is usual for Go packages) and a path to a [Go workspace](https://golang.org/doc/gopath_code.html#Workspaces), which can be the local GOPATH or any directory.

The plugins must be placed in the `./plugins-local` directory,
which should be in the working directory of the process running the Traefik binary.
The source code of the plugin should be organized as follows:

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

For local development, a `docker-compose.local.yml` is provided which reproduces the directory layout needed by Traefik.  
This works once you have generated and filled your _LAPI-KEY_ (lapiKey), if not read above for informations.

```bash
docker compose -f docker-compose.local.yml up -d
```

Equivalent to

```bash
make run_local
```

