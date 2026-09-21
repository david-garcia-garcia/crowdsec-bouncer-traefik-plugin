![GitHub](https://img.shields.io/github/license/david-garcia-garcia/crowdsec-bouncer-traefik-plugin)
![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/david-garcia-garcia/crowdsec-bouncer-traefik-plugin)
![GitHub tag (latest SemVer)](https://img.shields.io/github/v/tag/david-garcia-garcia/crowdsec-bouncer-traefik-plugin)
[![Build Status](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/workflows/main.yml/badge.svg)](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions)
[![Go Report Card](https://goreportcard.com/badge/github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin)](https://goreportcard.com/badge/github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin)

# Crowdsec Bouncer Traefik plugin

## What this plugin is

This plugin aims to implement a Crowdsec Bouncer in a Traefik plugin.

The purpose is to enable Traefik to authorize or block requests from IPs based on their reputation and behavior.

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

> [!WARNING]
> The LAPI stream has to be unique per LAPI key + bouncer IP. If you need more than one CrowdSec configuration inside the same Traefik instance, provision different API keys.

## Decisions

A CrowdSec decision is *who* (scope) plus *what* (remediation). This plugin looks up that pair.

Decision **scopes** supported by the plugin are `Ip`, `Range` (CIDR), and any other CrowdSec scope listed in `lapiScopeHeaders`.

`lapiScopeHeaders` maps a CrowdSec **scope name** (the map key) to a request **header name** (the map value). The key selects how the header is interpreted, not the header name:

- `Country` (any case: `country`, `Country`): ISO 3166-1 alpha-2, case-insensitive. Cloudflare `XX` and `T1` do not match. Example headers: `CF-IPCountry`, or `X-IPCountry` from a geoenrich middleware.
- `AS` (any case: `as`, `AS`): decimal ASN. A leading `AS` / `as` on the header or the decision is ignored. Example header: `CF-ASN`.
- Any other key (`username`, `session`, …): trimmed header string, compared as-is to the decision value. The key must match the scope LAPI stored (`username` is not `user`).
- `Ip` and `Range` cannot be mapped. IP comes from the client address; Range is CIDR containment.

```yaml
lapiScopeHeaders:
  Country: X-IPCountry
  AS: CF-ASN
  username: X-User
```

The plugin does not resolve GeoIP or invent header values. Every `lapiScopeHeaders` scope is taken from the request as-is (CDN, reverse proxy, or a Traefik middleware such as [traefik-geoblock](https://github.com/david-garcia-garcia/traefik-geoblock)). If the client can set that header, they can change matching — use only values you trust when the header is not client-controlled. A worked chain is in [examples/geoenrich-decisions](examples/geoenrich-decisions/README.md).

## Remediation

CrowdSec remediations this plugin applies ([CrowdSec bouncers](https://docs.crowdsec.net/u/bouncers/intro)):

| Remediation | What the user gets |
| ----------- | ------------------ |
| `ban`       | Ban page (or empty body) with `BouncerRemediationStatusCode` (default 403) |
| `captcha`   | A challenge page. After they pass, they are clean for a grace period, then challenged again if CrowdSec still has a decision. See [examples/captcha](examples/captcha/README.md). |

Captcha providers:

- [hCaptcha](https://www.hcaptcha.com/)
- [reCAPTCHA](https://www.google.com/recaptcha/about/)
- [Turnstile](https://www.cloudflare.com/products/turnstile/)
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

There are four LAPI fetch strategies (`lapiMode`). Sequence diagrams live in [docs/modes.md](docs/modes.md).

| Mode   | Summary |
| ------ | ------- |
| none   | Every request asks LAPI. No decision cache. Ban or captcha from that answer. |
| live   | Same as none, but caches each IP's result. |
| stream | Sync decisions from LAPI on an interval; the request path hits cache only. Recommended. |
| alone  | Like stream, but pulls the community blocklist from CAPI. No local CrowdSec. |

`stream` is recommended: decisions refresh every 60 seconds by default. The request path does not call LAPI. Usage-metrics still POST to LAPI on `LapiMetricsIntervalSeconds` unless that interval is zero or less.

`lapiMode` is the LAPI fetch strategy only. `lapiEnabled` (default true) and `appsecEnabled` (default false) turn each backend on. `bouncerEnabled` (default false) is whether this router remediates; otherwise Traefik calls `next`. AppSec-only is `lapiEnabled: false` plus `appsecEnabled: true`. The usual pair is `lapiMode: stream`, `appsecEnabled: true`, and `bouncerEnabled: true`.

## Named LAPI and AppSec instances

One middleware may still open LAPI, open AppSec, and bounce. That is the default one-router setup: put the LAPI key (and AppSec settings if you want WAF) on the bouncing middleware. Dummy or placeholder routers are optional.

When several bouncing routers should share one LAPI or AppSec client, give the opener secrets and an instance name, and let the others subscribe:

- `lapiEnabled: true` plus a LAPI key (or client cert, or alone CAPI login) **opens** the client and publishes `lapiInstance` (empty means the Traefik middleware name).
- `lapiEnabled: true`, `lapiInstance` set, and **no** LAPI secrets **subscribes**. `New` does not wait if that name is not published yet (Traefik constructors would deadlock). A request that Peeks a miss uses `bouncerLapiFailureAction`.
- The same four cases apply to AppSec (`appsecEnabled`, `appsecInstance`, `appsecKey`, `bouncerAppsecFailureAction`).
- `bouncerHold: true` still opens and publishes, then answers HTTP 503 without bouncing. Use that only on a placeholder router that should not serve origin traffic. You need a dummy router only when **no** bouncing router is willing to own the secrets.

`lapiScopeHeaders` is opener-only. Subscribers do not union into stream `scopes=`.

## Cache

The cache remembers CrowdSec remediations so this plugin does not have to ask LAPI on every request.

- **`live`**: stores each client result (banned, captcha, or clean) for `BouncerLiveTtlSeconds`. This is the mode where a shared Redis cache is useful: several Traefik replicas can reuse the same LAPI answers.
- **`stream` / `alone`**: stores the decision list locally. Prefer the in-memory store. Redis adds a network hop for a set you already sync on an interval.
- **`none`**: no decision cache to share. `lapiEnabled: false` also has no LAPI decision cache.

Captcha grace does not use this cache. After a passed challenge, the plugin sets a signed cookie (`crowdsec_captcha_gate`), not a cache key.

## Usage

To get started, use the `docker-compose.yml` file.

You can run it with:

```bash
make run
```

### Note

> [!IMPORTANT]
> You can declare many CrowdSec middlewares in one Traefik. Each router keeps its own request policy (`bouncerEnabled`, captcha, trusted IPs, failure actions, templates).
>
> CrowdSec LAPI still identifies **one stream per LAPI key + the IP this Traefik uses to call LAPI**. Middlewares that **open** that pair share the stream and the decision store. A ban on that store applies to every router that Peeks that LAPI instance.
>
> A second CrowdSec configuration (isolated decisions or a different stream) needs a **different LAPI key** and a different `lapiInstance`. Two stream configs on the same key from the same Traefik instance fight over one cursor.
>
> On a shared session, stream interval, `lapiUpdateMaxFailure`, and CAPI scenarios are create-time: the first opener to start keeps those values. `lapiScopeHeaders` is opener-only. Per-router bounce policy (`bouncerEnabled`, captcha, trusted IPs, failure actions, templates) does not have to match.

> [!WARNING]  
> **Appsec maximum body limit is defaulted to 10MB** > _Be careful when you upgrade to >1.4.x_

### Variables

**BouncerBanFile** (string, default `""`)
Path to the ban file. Empty disables it. Content-Type is inferred from the extension.

**BouncerCaptchaCustomChallengeURL** (string, default `""`)
`custom` only. Origin widget challenge URL (Wicketkeeper: `http://captcha.localhost:8000/v0/challenge`). Rendered as `{{ .ChallengeURL }}`. A captcha-flagged client may request this exact path and it is passed through (banned clients are not). Empty means no challenge passthrough.

**BouncerCaptchaCustomJsURL** (string, no default)
`custom` only. URL that loads the challenge in HTML (hCaptcha: `https://hcaptcha.com/1/api.js`). When the widget is on the protected router, a captcha-flagged client may request this exact path and it is passed through (banned clients are not).

**BouncerCaptchaCustomKey** (string, no default)
`custom` only. CSS class of the captcha div (hCaptcha: `h-captcha`).

**BouncerCaptchaCustomResponse** (string, no default)
`custom` only. POST field from `captcha.html` (hCaptcha: `h-captcha-response`).

**BouncerCaptchaCustomValidateBody** (string, default `""`)
Siteverify request encoding. After trim, exact lowercase `""` or `form` POSTs `application/x-www-form-urlencoded` `secret` and `response` (same as omit; Wicketkeeper). `json` POSTs `application/json` `{"secret","response"}`. `json` is `custom` only — a built-in plus `json` fails startup. `JSON`, `Form`, and any other token fail for every provider.

CapJS / Cap Standalone as `custom` (operator HTML stays yours; no `trycap` provider):

```yaml
bouncerCaptchaProvider: custom
bouncerCaptchaCustomJsUrl: https://<instance>/assets/widget.js
bouncerCaptchaCustomKey: cap
bouncerCaptchaCustomResponse: cap-token
bouncerCaptchaCustomValidateUrl: https://<instance>/<site_key>/siteverify
bouncerCaptchaCustomValidateBody: json
bouncerCaptchaSiteKey: FIXME
bouncerCaptchaSecretKey: FIXME
bouncerCaptchaGateSecret: FIXME
```

**BouncerCaptchaCustomValidateURL** (string, no default)
`custom` only. URL that validates the challenge (hCaptcha: `https://api.hcaptcha.com/siteverify`). Cap Standalone: `https://<instance>/<site_key>/siteverify` with `BouncerCaptchaCustomValidateBody: json`.

**BouncerCaptchaFile** (string, default `/captcha.html`)
Path to the captcha template. Content-Type is inferred from the extension.

**CaptchaGateBindIp** (bool, default `true`)
When true, the gate cookie binds to the client IP from `GetRemoteIP`. When false, grace is cookie-only (HMAC + expiry).

**BouncerCaptchaGateSecret** (string, no default)
HMAC secret for the stateless captcha grace cookie (`crowdsec_captcha_gate`). Required when `BouncerCaptchaProvider` is set. Not the same as `BouncerCaptchaSecretKey`.

**BouncerCaptchaGateSecretFile** (string, no default)
File path for `BouncerCaptchaGateSecret` (preferred over an inline secret when both are set).

**BouncerCaptchaGracePeriodSeconds** (int64, default `1800` / 30 minutes)
How long after a passed captcha before a new challenge, if the CrowdSec decision is still valid.

**BouncerCaptchaProvider** (string, no default)
Captcha validator. Expected: `hcaptcha`, `recaptcha`, `turnstile`, `custom`.

**BouncerCaptchaSecretKey** (string, no default)
Site secret key for the captcha provider.

**BouncerCaptchaSiteKey** (string, no default)
Site key for the captcha provider.

**BouncerCaptchaHttpTimeoutSeconds** (int64, default `0`)
Timeout in seconds for the captcha provider siteverify client. Zero or omitted inherits `HTTPTimeoutSeconds`.

**BouncerClientTrustedIPs** ([]string, default `[]`)
Client IPs that bypass bouncer and cache checks (LAN or VPN). Trusted clients also skip AppSec.

**AppsecBodyLimit** (int64, default `10485760` / 10MB)
Send only the first N bytes to AppSec. `0` is unlimited. Only POST, PUT, PATCH, and DELETE bodies are forwarded; any other method (including a GET with a body) is sent as a headers-only GET with the real verb on `X-Crowdsec-Appsec-Verb`.

**AppsecEnabled** (bool, default `false`)
Enable CrowdSec AppSec (WAF). Independent of `LapiMode`: it inspects the requests the decision check allowed, in every mode. CrowdSec 1.8 bot-detection needs this set, plus a Traefik router `PathPrefix(/crowdsec-internal/challenge)` using this same middleware.

**BouncerAppsecFailureAction** (string, default `ban`)
What to do when AppSec does not return a usable verdict (HTTP 500, unreachable, body read error, or unreadable HTTP/2 or HTTP/3 body on POST/PUT/PATCH). Expected: `passthrough`, `ban`, `captcha`. `ban` drops the request. `passthrough` lets 500/unreachable/body-io errors continue as allow, and sends a headers-only GET when the body cannot be buffered. `captcha` uses the plugin captcha client (`bouncerCaptchaProvider` must be set). **BREAKING:** replaces `crowdsecAppsecFailureBlock`, `crowdsecAppsecUnreachableBlock`, and `crowdsecAppsecUnreadableBodyBlock`. Operators who had those bools set to `false` MUST set `bouncerAppsecFailureAction: passthrough`.

**AppsecHost** (string, default `"crowdsec:7422"`)
AppSec host and port.

**AppsecHttpTimeoutSeconds** (int64, default `0`)
Timeout in seconds when contacting AppSec. Zero or omitted inherits `HTTPTimeoutSeconds`. Example: `appsecHttpTimeoutSeconds: 1` with `bouncerAppsecFailureAction: passthrough` so an AppSec hang fails open after one second instead of the shared default.

**AppsecKey** (string, default value of `LapiKey`)
AppSec key for the bouncer.

**AppsecPath** (string, default `"/"`)
AppSec path, appended to `AppsecHost`. Must end with `/`.

**AppsecScheme** (string, default value of `LapiScheme`)
Expected: `http`, `https`.

**CrowdsecAppsecTlsCertificateAuthority** (string, default `""`)
PEM CA used to verify AppSec's server certificate. When empty (and `appsecTlsInsecureVerify` is `false`), the host system trust store is used.

**CrowdsecAppsecTlsInsecureVerify** (bool, default `false`)
Disable verification of the certificate presented by AppSec.

**CrowdsecCapiMachineId** (string, no default)
`alone` only. CAPI login.

**LapiCapiPassword** (string, no default)
`alone` only. CAPI password.

**LapiCapiScenarios** ([]string, no default)
`alone` only. CAPI scenarios.

**BouncerDecisionHeader** (string, default `""`)
Incoming request header that forces ban or captcha. Empty disables the feature (the plugin does not read `X-Crowdsec-Decision` unless you set this key). Values are exact trimmed `b` (ban) or `c` (captcha). `b` applies ban without a stream or live lookup. `c` still consults that lookup: a CrowdSec ban wins and the plugin logs WARN `ServeHTTP:forcedCaptchaSuperseded`; otherwise captcha. Any other token, including `t` and `B`, is ignored and lookup continues. Put a Traefik middleware that writes this header *before* the bouncer. Do not expose the header to the internet; any client who can set it can captcha or ban themselves. A `c` value still honors the captcha gate cookie when lookup is not ban: a visitor who already solved captcha reaches origin even while the header is still `c`. Trusted client IPs still skip the whole plugin, including this header.

**BouncerLapiFailureAction** (string, default `ban`)
What to do when LAPI does not return a usable verdict (live/none HTTP or parse error, or a cache miss while stream/alone is unhealthy after `lapiUpdateMaxFailure`). Expected: `passthrough`, `ban`, `captcha`. Cache hits still apply when the stream is unhealthy. `passthrough` uses the pass path (AppSec still runs if enabled). `captcha` uses the plugin captcha client (`bouncerCaptchaProvider` must be set). **Behavior change:** in `live` and `none`, this action also covers a failed `lapiScopeHeaders` query. Previously a LAPI that answered the IP query but errored on a header-scope query was treated as "no decision" and allowed (`DEBUG`). That is now a LAPI failure: default `ban` blocks those requests and logs `WARN`. An active ban still wins. Set `bouncerLapiFailureAction: passthrough` to keep allowing when a header-scope query fails.

**LapiHost** (string, default `"crowdsec:8080"`)
LAPI host and port.

**LapiHttpTimeoutSeconds** (int64, default `0`)
Timeout in seconds when contacting LAPI. Zero or omitted inherits `HTTPTimeoutSeconds`.

**LapiKey** (string, default `""`)
LAPI key for the bouncer.

**LapiPath** (string, default `"/"`)
LAPI path, appended to `LapiHost`. Must end with `/`.

**LapiScheme** (string, default `http`)
Expected: `http`, `https`.

**CrowdsecLapiTlsCertificateAuthority** (string, default `""`)
PEM CA used to verify LAPI's server certificate. When empty (and `lapiTlsInsecureVerify` is `false`), the host system trust store is used.

**CrowdsecLapiTlsCertificateBouncer** (string, default `""`)
PEM client certificate of the bouncer.

**CrowdsecLapiTlsCertificateBouncerKey** (string, default `""`)
PEM client private key of the bouncer.

**CrowdsecLapiTlsInsecureVerify** (bool, default `false`)
Disable verification of the certificate presented by LAPI.

**LapiMode** (string, default `live`)
Expected: `none`, `live`, `stream`, `alone`, `appsec`.

**LapiScopeHeaders** (map[string]string, default `{}`)
Maps a CrowdSec scope name (key) to a request header (value). `Country` (any case) is ISO 3166-1 alpha-2 and ignores `XX`/`T1`; `AS` (any case) is decimal digits and strips a leading `AS`; any other key is a trimmed exact match. Do not map `Ip` or `Range`. Empty disables header scopes. This plugin does not geolocate. See the `lapiScopeHeaders` example above.

**BouncerLiveTtlSeconds** (int64, default `60`)
`live` only. Maximum decision duration.

**Enabled** (bool, default `false`)
Enable the plugin.

**BouncerForwardedHeader** (string, default `"X-Forwarded-For"`)
Header that holds the real client IP. Read only when the socket peer is in `BouncerForwardedTrustedIPs`. That list also skips hops in the header right-to-left; the first value not in the list wins. `X-Real-Ip` is trustworthy only when the front proxy sets it. Traefik's entrypoint deletes `X-Forwarded-*` and `X-Real-Ip` from untrusted peers and only writes `X-Real-Ip` when absent, filling it with the socket peer. Cloudflare sends `CF-Connecting-IP` and `X-Forwarded-For` but not `X-Real-Ip`, so Traefik would fill in the Cloudflare edge and every visitor would be remediated as Cloudflare. Use `X-Real-Ip` with an nginx or HAProxy front that sets it.

**BouncerForwardedInsecure** (bool, default `false`)
Skip the socket-peer gate, treat the named header as a single client address with no hop walk, and default the header to `X-Real-Ip` when `BouncerForwardedHeader` is still `X-Forwarded-For`. Safe only when the Traefik entrypoint has `forwardedHeaders.trustedIPs` set and is not running with `forwardedHeaders.insecure: true`. Otherwise any client can choose which IP this plugin bans, captchas, and caches.

**BouncerForwardedTrustedIPs** ([]string, default `[]`)
IPs of trusted proxies in front of Traefik (for example Cloudflare). The forwarded header is honored only when the connecting peer is in this list. While empty, forwarded headers are ignored and the plugin remediates the connecting address. If Traefik sits behind a load balancer or CDN, list it here or every visitor is remediated as the proxy. Without `BouncerForwardedInsecure` there is no way to trust every peer. A catch-all `0.0.0.0/0` plus `::/0` passes the peer check but then treats the header value as a trusted hop and falls back to the connecting address with no warning (peer `203.0.113.7`, `X-Real-Ip: 198.51.100.9` resolves to `203.0.113.7`). `0.0.0.0/0` is IPv4 only and `::/0` is IPv6 only. Private ranges `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` are the alternative to enumerating proxies on a private ingress: the peer must be inside a listed range and the real client must not. Verified working: pool `172.16.0.0/12`, peer `172.18.0.5`, `X-Real-Ip: 198.51.100.9` → `198.51.100.9`. Verified failure: pool `10.0.0.0/8`, peer `10.1.2.3`, `X-Real-Ip: 10.9.9.9` → `10.1.2.3`.

**HTTPTimeoutSeconds** (int64, default `10`)
Shared default timeout in seconds for LAPI, AppSec, and captcha siteverify. Per-backend knobs inherit this value when they are zero or omitted.

**LogFilePath** (string, default `""`)
File path for logs. Must be writable by Traefik. Rotation may need a Traefik restart.

**LogFormat** (string, default `common`)
`common` for text logs, `json` for structured JSON. Expected: `common`, `json`.

**LogLevel** (string, default `INFO`)
Logs go to `stdout` / `stderr`, or to a file if `LogFilePath` is set. Expected: `TRACE`, `DEBUG`, `INFO`, `WARN`, `ERROR`. `TRACE` is for per-request breadcrumbs (`ServeHTTP`, captcha check); `DEBUG` is for startup, stream ticks, and request-path failures.

**LapiMetricsIntervalSeconds** (int64, default `600`)
Seconds between metrics updates to CrowdSec. Zero or less disables collection.

**BouncerDecisionRemap** (map[string]map[string]string, default `{}`)
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
Redis replica hosts for reads (round-robin). Falls back to `LapiRedisHost` when empty. When set, reads are not retried against the primary if replicas are unreachable. With `BouncerRedisUnreachableBlock` at its default (`true`), a replica outage blocks or delays requests even if the primary is healthy.

**BouncerRedisUnreachableBlock** (bool, default `true`)
Block the request when Redis is unreachable (adds a 1-second delay per request).

**BouncerRemediationHeader** (string, default `""`)
Response header name when the plugin handles the request. Header value is `ban`, `captcha`, `solved-captcha`, or `error:client-disconnected` (client dropped the body while AppSec was buffering; not a ban). Include this header in Traefik `accessLog.fields.headers` if you want disconnects in access logs. Empty disables the header.

**BouncerRemediationStatusCode** (int, default `403`)
HTTP status for a banned user (not captcha).

**LapiStreamStartupBlock** (bool, default `true`)
`stream` and `alone` only. When `true`, plugin init waits for CrowdSec before serving traffic. When `false`, all requests bypass remediation until the first stream sync — banned IPs are allowed in that window. Only disable when startup availability matters more than blocking at startup.

**BouncerTraceHeader** (string, default `""`)
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
          logLevel: DEBUG
          lapiMode: live
          lapiKey: privateKey-foo
          lapiHost: crowdsec:8080
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
          bouncerEnabled: true
          lapiEnabled: true
          lapiInstance: ""
          appsecInstance: ""
          bouncerHold: false
          logLevel: DEBUG
          logFormat: common
          logFilePath: ""
          lapiUpdateIntervalSeconds: 60
          lapiUpdateMaxFailure: 0
          bouncerLapiFailureAction: ban
          lapiStreamStartupBlock: true
          bouncerLiveTtlSeconds: 60
          bouncerRemediationStatusCode: 403
          httpTimeoutSeconds: 10
          lapiHttpTimeoutSeconds: 0
          bouncerCaptchaHttpTimeoutSeconds: 0
          lapiMode: live
          appsecEnabled: false
          appsecScheme: ""
          appsecHost: crowdsec:7422
          appsecPath: "/"
          appsecHttpTimeoutSeconds: 1
          bouncerAppsecFailureAction: passthrough
          appsecBodyLimit: 10485760
          lapiKey: privateKey-foo
          lapiScheme: http
          lapiHost: crowdsec:8080
          lapiPath: "/"
          lapiTlsInsecureVerify: false
          lapiCapiMachineId: login
          lapiCapiPassword: password
          lapiCapiScenarios:
            - crowdsecurity/http-path-traversal-probing
            - crowdsecurity/http-xss-probing
            - crowdsecurity/http-generic-bf
          bouncerForwardedTrustedIps:
            - 10.0.10.23/32
            - 10.0.20.0/24
          bouncerClientTrustedIps:
            - 192.168.1.0/24
          bouncerForwardedHeader: X-Custom-Header
          lapiScopeHeaders: {}
            # Country: X-IPCountry    # key Country (any case) → ISO country matcher (CDN or geoenrich)
            # AS: CF-ASN             # key AS (any case) → ASN matcher
            # username: X-User       # any other key → trimmed exact match
          bouncerDecisionHeader: X-Crowdsec-Decision # optional; earlier middleware writes b or c
          bouncerRemediationHeader: cs-remediation
          lapiRedisEnabled: false
          lapiRedisHost: "redis-primary:6379"
          lapiRedisReadHosts:
            - "redis-replica-1:6379"
            - "redis-replica-2:6379"
          lapiRedisPassword: password
          lapiRedisDatabase: "5"
          bouncerRedisUnreachableBlock: true
          lapiTlsCa: |-
            -----BEGIN CERTIFICATE-----
            MIIEBzCCAu+gAwIBAgICEAAwDQYJKoZIhvcNAQELBQAwgZQxCzAJBgNVBAYTAlVT
            ...
            Q0veeNzBQXg1f/JxfeA39IDIX1kiCf71tGlT
            -----END CERTIFICATE-----
          lapiTlsCert: |-
            -----BEGIN CERTIFICATE-----
            MIIEHjCCAwagAwIBAgIUOBTs1eqkaAUcPplztUr2xRapvNAwDQYJKoZIhvcNAQEL
            ...
            RaXAnYYUVRblS1jmePemh388hFxbmrpG2pITx8B5FMULqHoj11o2Rl0gSV6tHIHz
            N2U=
            -----END CERTIFICATE-----
          lapiTlsKey: |-
            -----BEGIN RSA PRIVATE KEY-----
            MIIEogIBAAKCAQEAtYQnbJqifH+ZymePylDxGGLIuxzcAUU4/ajNj+qRAdI/Ux3d
            ...
            ic5cDRo6/VD3CS3MYzyBcibaGaV34nr0G/pI+KEqkYChzk/PZRA=
            -----END RSA PRIVATE KEY-----
          bouncerCaptchaProvider: hcaptcha
          bouncerCaptchaSiteKey: FIXME
          bouncerCaptchaSecretKey: FIXME
          bouncerCaptchaGateSecret: FIXME
          bouncerCaptchaGracePeriodSeconds: 1800
          bouncerDecisionRemap:
            CAPI:
              ban: captcha
            lists:firehol_level1:
              ban: captcha
          bouncerCaptchaFile: /captcha.html
          bouncerBanFile: /ban.html
          bouncerTraceHeader: X-Request-ID
          lapiMetricsIntervalSeconds: 600
```

#### Fill variable with value of file

`LapiTlsKey`, `LapiTlsCert`, `LapiTlsCa`, `AppsecTlsCa`, `LapiCapiMachineId`, `LapiCapiPassword`, `LapiKey`, `AppsecKey`, `BouncerCaptchaSiteKey`, `BouncerCaptchaSecretKey`, `BouncerCaptchaGateSecret` and `LapiRedisPassword` can be provided with the content as raw or through a file path that Traefik can read.  
The file variable will be used as preference if both content and file are provided for the same variable.

Format is:

- Content: VariableName: XXX
- File : VariableNameFile: /path

#### Authenticate with LAPI

You can authenticate to the LAPI either with LAPIKEY or by using client certificates.  
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

- **Publicly trusted certificate** (e.g. Let's Encrypt behind a reverse proxy): leave `lapiTlsCa` empty and `lapiTlsInsecureVerify` `false`. The plugin falls back to the host's system trust store (the `traefik` image ships `ca-certificates`).
- **Private/self-signed CA**: set `lapiTlsCa` (or `lapiTlsCaFile`) to the PEM-encoded CA that signed Crowdsec's server cert.
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

### About

This plugin is a fork of [maxlerebourg/crowdsec-bouncer-traefik-plugin](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin).

