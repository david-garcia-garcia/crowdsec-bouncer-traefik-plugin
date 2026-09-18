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

Decision **scopes** supported by the plugin are `Ip`, `Range` (CIDR), and any other CrowdSec scope listed in `decisionScopeHeaders`.

`decisionScopeHeaders` maps a CrowdSec **scope name** (the map key) to a request **header name** (the map value). The key selects how the header is interpreted, not the header name:

- `Country` (any case: `country`, `Country`): ISO 3166-1 alpha-2, case-insensitive. Cloudflare `XX` and `T1` do not match. Example headers: `CF-IPCountry`, or `X-IPCountry` from a geoenrich middleware.
- `AS` (any case: `as`, `AS`): decimal ASN. A leading `AS` / `as` on the header or the decision is ignored. Example header: `CF-ASN`.
- Any other key (`username`, `session`, …): trimmed header string, compared as-is to the decision value. The key must match the scope LAPI stored (`username` is not `user`).
- `Ip` and `Range` cannot be mapped. IP comes from the client address; Range is CIDR containment.

```yaml
decisionScopeHeaders:
  Country: X-IPCountry
  AS: CF-ASN
  username: X-User
```

The plugin does not resolve GeoIP or invent header values. Every `decisionScopeHeaders` scope is taken from the request as-is (CDN, reverse proxy, or a Traefik middleware such as [traefik-geoblock](https://github.com/david-garcia-garcia/traefik-geoblock)). If the client can set that header, they can change matching — use only values you trust when the header is not client-controlled. A worked chain is in [examples/geoenrich-decisions](examples/geoenrich-decisions/README.md).

## Remediation

CrowdSec remediations this plugin applies ([CrowdSec bouncers](https://docs.crowdsec.net/u/bouncers/intro)):

| Remediation | What the user gets |
| ----------- | ------------------ |
| `ban`       | Ban page (or empty body) with `RemediationStatusCode` (default 403) |
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

There are five operating modes (`CrowdsecMode`). Sequence diagrams live in [docs/modes.md](docs/modes.md).

| Mode   | Summary |
| ------ | ------- |
| none   | Every request asks LAPI. No decision cache. Ban or captcha from that answer. |
| live   | Same as none, but caches each IP's result. |
| stream | Sync decisions from LAPI on an interval; the request path hits cache only. Recommended. |
| alone  | Like stream, but pulls the community blocklist from CAPI. No local CrowdSec. |
| appsec | Skip IP decisions; send the HTTP request to AppSec. Use when IP checks happen elsewhere. |

`stream` is recommended: decisions refresh every 60 seconds by default. The request path does not call LAPI. Usage-metrics still POST to LAPI on `MetricsUpdateIntervalSeconds` unless that interval is zero or less.

`CrowdsecMode` and `CrowdsecAppsecEnabled` are independent axes. The mode picks where decisions come from; `CrowdsecAppsecEnabled` adds the AppSec (WAF) check, which inspects the requests the decision check allowed, in **every** mode. The usual pair is `stream` plus `crowdsecAppsecEnabled: true`. Because `appsec` mode has no decision source, it is the one mode that needs AppSec enabled to do anything: `crowdsecMode: appsec` with `crowdsecAppsecEnabled: false` enforces nothing and every request reaches your service. The plugin logs a warning at startup for that pair and still starts.

## Cache

The cache remembers CrowdSec remediations so this plugin does not have to ask LAPI on every request.

- **`live`**: stores each client result (banned, captcha, or clean) for `DefaultDecisionSeconds`. This is the mode where a shared Redis cache is useful: several Traefik replicas can reuse the same LAPI answers.
- **`stream` / `alone`**: stores the decision list locally. Prefer the in-memory store. Redis adds a network hop for a set you already sync on an interval.
- **`none` / `appsec`**: no decision cache to share.

Captcha grace does not use this cache. After a passed challenge, the plugin sets a signed cookie (`crowdsec_captcha_gate`), not a cache key.

## Usage

To get started, use the `docker-compose.yml` file.

You can run it with:

```bash
make run
```

### Note

> [!IMPORTANT]
> You can declare many CrowdSec middlewares in one Traefik. Each router keeps its own request policy (enabled, captcha, trusted IPs, failure actions, templates).
>
> CrowdSec LAPI still identifies **one stream per LAPI key + the IP this Traefik uses to call LAPI**. Middlewares that share that pair share the stream and the decision store. A ban on that store applies to every router on that session.
>
> A second CrowdSec configuration (isolated decisions or a different stream) needs a **different LAPI key**. Two stream configs on the same key from the same Traefik instance fight over one cursor.
>
> On a shared session, stream interval, `updateMaxFailure`, and CAPI scenarios are create-time: the first middleware to start keeps those values. `decisionScopeHeaders` is not first-wins: live routers on that Client union their maps into stream `scopes=`. Per-router policy (enabled, captcha, trusted IPs, failure actions, templates) does not have to match.

> [!WARNING]  
> **Appsec maximum body limit is defaulted to 10MB** > _Be careful when you upgrade to >1.4.x_

### Variables

**BanFilePath** (string, default `""`)
Path to the ban file. Empty disables it. Content-Type is inferred from the extension.

**CaptchaCustomChallengeURL** (string, default `""`)
`custom` only. Origin widget challenge URL (Wicketkeeper: `http://captcha.localhost:8000/v0/challenge`). Rendered as `{{ .ChallengeURL }}`. A captcha-flagged client may request this exact path and it is passed through (banned clients are not). Empty means no challenge passthrough.

**CaptchaCustomJsURL** (string, no default)
`custom` only. URL that loads the challenge in HTML (hCaptcha: `https://hcaptcha.com/1/api.js`). When the widget is on the protected router, a captcha-flagged client may request this exact path and it is passed through (banned clients are not).

**CaptchaCustomKey** (string, no default)
`custom` only. CSS class of the captcha div (hCaptcha: `h-captcha`).

**CaptchaCustomResponse** (string, no default)
`custom` only. POST field from `captcha.html` (hCaptcha: `h-captcha-response`).

**CaptchaCustomValidateBody** (string, default `""`)
Siteverify request encoding. After trim, exact lowercase `""` or `form` POSTs `application/x-www-form-urlencoded` `secret` and `response` (same as omit; Wicketkeeper). `json` POSTs `application/json` `{"secret","response"}`. `json` is `custom` only — a built-in plus `json` fails startup. `JSON`, `Form`, and any other token fail for every provider.

CapJS / Cap Standalone as `custom` (operator HTML stays yours; no `trycap` provider):

```yaml
captchaProvider: custom
captchaCustomJsUrl: https://<instance>/assets/widget.js
captchaCustomKey: cap
captchaCustomResponse: cap-token
captchaCustomValidateUrl: https://<instance>/<site_key>/siteverify
captchaCustomValidateBody: json
captchaSiteKey: FIXME
captchaSecretKey: FIXME
captchaGateSecret: FIXME
```

**CaptchaCustomValidateURL** (string, no default)
`custom` only. URL that validates the challenge (hCaptcha: `https://api.hcaptcha.com/siteverify`). Cap Standalone: `https://<instance>/<site_key>/siteverify` with `CaptchaCustomValidateBody: json`.

**CaptchaFilePath** (string, default `/captcha.html`)
Path to the captcha template. Content-Type is inferred from the extension.

**CaptchaGateBindIp** (bool, default `true`)
When true, the gate cookie binds to the client IP from `GetRemoteIP`. When false, grace is cookie-only (HMAC + expiry).

**CaptchaGateSecret** (string, no default)
HMAC secret for the stateless captcha grace cookie (`crowdsec_captcha_gate`). Required when `CaptchaProvider` is set. Not the same as `CaptchaSecretKey`.

**CaptchaGateSecretFile** (string, no default)
File path for `CaptchaGateSecret` (preferred over an inline secret when both are set).

**CaptchaGracePeriodSeconds** (int64, default `1800` / 30 minutes)
How long after a passed captcha before a new challenge, if the CrowdSec decision is still valid.

**CaptchaProvider** (string, no default)
Captcha validator. Expected: `hcaptcha`, `recaptcha`, `turnstile`, `custom`.

**CaptchaSecretKey** (string, no default)
Site secret key for the captcha provider.

**CaptchaSiteKey** (string, no default)
Site key for the captcha provider.

**ClientTrustedIPs** ([]string, default `[]`)
Client IPs that bypass bouncer and cache checks (LAN or VPN). Trusted clients also skip AppSec.

**CrowdsecAppsecBodyLimit** (int64, default `10485760` / 10MB)
Send only the first N bytes to AppSec. `0` is unlimited. Only POST, PUT, PATCH, and DELETE bodies are forwarded; any other method (including a GET with a body) is sent as a headers-only GET with the real verb on `X-Crowdsec-Appsec-Verb`.

**CrowdsecAppsecEnabled** (bool, default `false`)
Enable CrowdSec AppSec (WAF). Independent of `CrowdsecMode`: it inspects the requests the decision check allowed, in every mode. CrowdSec 1.8 bot-detection needs this set, plus a Traefik router `PathPrefix(/crowdsec-internal/challenge)` using this same middleware.

**CrowdsecAppsecFailureAction** (string, default `ban`)
What to do when AppSec does not return a usable verdict (HTTP 500, unreachable, body read error, or unreadable HTTP/2 or HTTP/3 body on POST/PUT/PATCH). Expected: `passthrough`, `ban`, `captcha`. `ban` drops the request. `passthrough` lets 500/unreachable/body-io errors continue as allow, and sends a headers-only GET when the body cannot be buffered. `captcha` uses the plugin captcha client (`captchaProvider` must be set). **BREAKING:** replaces `crowdsecAppsecFailureBlock`, `crowdsecAppsecUnreachableBlock`, and `crowdsecAppsecUnreadableBodyBlock`. Operators who had those bools set to `false` MUST set `crowdsecAppsecFailureAction: passthrough`.

**CrowdsecAppsecHost** (string, default `"crowdsec:7422"`)
AppSec host and port.

**CrowdsecAppsecKey** (string, default value of `CrowdsecLapiKey`)
AppSec key for the bouncer.

**CrowdsecAppsecPath** (string, default `"/"`)
AppSec path, appended to `CrowdsecAppsecHost`. Must end with `/`.

**CrowdsecAppsecScheme** (string, default value of `CrowdsecLapiScheme`)
Expected: `http`, `https`.

**CrowdsecAppsecTlsCertificateAuthority** (string, default `""`)
PEM CA used to verify AppSec's server certificate. When empty (and `crowdsecAppsecTlsInsecureVerify` is `false`), the host system trust store is used.

**CrowdsecAppsecTlsInsecureVerify** (bool, default `false`)
Disable verification of the certificate presented by AppSec.

**CrowdsecCapiMachineId** (string, no default)
`alone` only. CAPI login.

**CrowdsecCapiPassword** (string, no default)
`alone` only. CAPI password.

**CrowdsecCapiScenarios** ([]string, no default)
`alone` only. CAPI scenarios.

**CrowdsecLapiFailureAction** (string, default `ban`)
What to do when LAPI does not return a usable verdict (live/none HTTP or parse error, or a cache miss while stream/alone is unhealthy after `updateMaxFailure`). Expected: `passthrough`, `ban`, `captcha`. Cache hits still apply when the stream is unhealthy. `passthrough` uses the pass path (AppSec still runs if enabled). `captcha` uses the plugin captcha client (`captchaProvider` must be set). **Behavior change:** in `live` and `none`, this action also covers a failed `decisionScopeHeaders` query. Previously a LAPI that answered the IP query but errored on a header-scope query was treated as "no decision" and allowed (`DEBUG`). That is now a LAPI failure: default `ban` blocks those requests and logs `WARN`. An active ban still wins. Set `crowdsecLapiFailureAction: passthrough` to keep allowing when a header-scope query fails.

**CrowdsecLapiHost** (string, default `"crowdsec:8080"`)
LAPI host and port.

**CrowdsecLapiKey** (string, default `""`)
LAPI key for the bouncer.

**CrowdsecLapiPath** (string, default `"/"`)
LAPI path, appended to `CrowdsecLapiHost`. Must end with `/`.

**CrowdsecLapiScheme** (string, default `http`)
Expected: `http`, `https`.

**CrowdsecLapiTlsCertificateAuthority** (string, default `""`)
PEM CA used to verify LAPI's server certificate. When empty (and `crowdsecLapiTlsInsecureVerify` is `false`), the host system trust store is used.

**CrowdsecLapiTlsCertificateBouncer** (string, default `""`)
PEM client certificate of the bouncer.

**CrowdsecLapiTlsCertificateBouncerKey** (string, default `""`)
PEM client private key of the bouncer.

**CrowdsecLapiTlsInsecureVerify** (bool, default `false`)
Disable verification of the certificate presented by LAPI.

**CrowdsecMode** (string, default `live`)
Expected: `none`, `live`, `stream`, `alone`, `appsec`.

**DecisionScopeHeaders** (map[string]string, default `{}`)
Maps a CrowdSec scope name (key) to a request header (value). `Country` (any case) is ISO 3166-1 alpha-2 and ignores `XX`/`T1`; `AS` (any case) is decimal digits and strips a leading `AS`; any other key is a trimmed exact match. Do not map `Ip` or `Range`. Empty disables header scopes. This plugin does not geolocate. See the `decisionScopeHeaders` example above.

**DefaultDecisionSeconds** (int64, default `60`)
`live` only. Maximum decision duration.

**Enabled** (bool, default `false`)
Enable the plugin.

**ForwardedHeadersCustomName** (string, default `"X-Forwarded-For"`)
Header that holds the real client IP. Read only when the socket peer is in `ForwardedHeadersTrustedIPs`. That list also skips hops in the header right-to-left; the first value not in the list wins. `X-Real-Ip` is trustworthy only when the front proxy sets it. Traefik's entrypoint deletes `X-Forwarded-*` and `X-Real-Ip` from untrusted peers and only writes `X-Real-Ip` when absent, filling it with the socket peer. Cloudflare sends `CF-Connecting-IP` and `X-Forwarded-For` but not `X-Real-Ip`, so Traefik would fill in the Cloudflare edge and every visitor would be remediated as Cloudflare. Use `X-Real-Ip` with an nginx or HAProxy front that sets it.

**ForwardedHeadersInsecure** (bool, default `false`)
Skip the socket-peer gate, treat the named header as a single client address with no hop walk, and default the header to `X-Real-Ip` when `ForwardedHeadersCustomName` is still `X-Forwarded-For`. Safe only when the Traefik entrypoint has `forwardedHeaders.trustedIPs` set and is not running with `forwardedHeaders.insecure: true`. Otherwise any client can choose which IP this plugin bans, captchas, and caches.

**ForwardedHeadersTrustedIPs** ([]string, default `[]`)
IPs of trusted proxies in front of Traefik (for example Cloudflare). The forwarded header is honored only when the connecting peer is in this list. While empty, forwarded headers are ignored and the plugin remediates the connecting address. If Traefik sits behind a load balancer or CDN, list it here or every visitor is remediated as the proxy. Without `ForwardedHeadersInsecure` there is no way to trust every peer. A catch-all `0.0.0.0/0` plus `::/0` passes the peer check but then treats the header value as a trusted hop and falls back to the connecting address with no warning (peer `203.0.113.7`, `X-Real-Ip: 198.51.100.9` resolves to `203.0.113.7`). `0.0.0.0/0` is IPv4 only and `::/0` is IPv6 only. Private ranges `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` are the alternative to enumerating proxies on a private ingress: the peer must be inside a listed range and the real client must not. Verified working: pool `172.16.0.0/12`, peer `172.18.0.5`, `X-Real-Ip: 198.51.100.9` → `198.51.100.9`. Verified failure: pool `10.0.0.0/8`, peer `10.1.2.3`, `X-Real-Ip: 10.9.9.9` → `10.1.2.3`.

**HTTPTimeoutSeconds** (int64, default `10`)
Timeout in seconds when contacting LAPI.

**LogFilePath** (string, default `""`)
File path for logs. Must be writable by Traefik. Rotation may need a Traefik restart.

**LogFormat** (string, default `common`)
`common` for text logs, `json` for structured JSON. Expected: `common`, `json`.

**LogLevel** (string, default `INFO`)
Logs go to `stdout` / `stderr`, or to a file if `LogFilePath` is set. Expected: `DEBUG`, `INFO`, `WARN`, `ERROR`.

**MetricsUpdateIntervalSeconds** (int64, default `600`)
Seconds between metrics updates to CrowdSec. Zero or less disables collection.

**RedisCacheDatabase** (string, default `""`)
Redis database selection.

**RedisCacheEnabled** (bool, default `false`)
Use Redis instead of in-memory cache.

**RedisCacheHost** (string, default `"redis:6379"`)
Redis write host (primary), `host:port`.

**RedisCachePassword** (string, default `""`)
Redis password.

**RedisCacheReadHosts** ([]string, default `[]`)
Redis replica hosts for reads (round-robin). Falls back to `RedisCacheHost` when empty. When set, reads are not retried against the primary if replicas are unreachable. With `RedisCacheUnreachableBlock` at its default (`true`), a replica outage blocks or delays requests even if the primary is healthy.

**RedisCacheUnreachableBlock** (bool, default `true`)
Block the request when Redis is unreachable (adds a 1-second delay per request).

**RemediationHeadersCustomName** (string, default `""`)
Response header name when the plugin handles the request. Header value is `ban`, `captcha`, or `solved-captcha`.

**RemediationStatusCode** (int, default `403`)
HTTP status for a banned user (not captcha).

**StreamStartupBlock** (bool, default `true`)
`stream` and `alone` only. When `true`, plugin init waits for CrowdSec before serving traffic. When `false`, all requests bypass remediation until the first stream sync — banned IPs are allowed in that window. Only disable when startup availability matters more than blocking at startup.

**TraceHeadersCustomName** (string, default `""`)
Request header whose value is injected into the ban HTML. Empty disables it.

**UpdateIntervalSeconds** (int64, default `60`)
`stream` only. Interval between LAPI blacklist fetches.

**UpdateMaxFailure** (int64, default `0`)
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
          enabled: true
          logLevel: DEBUG
          crowdsecMode: live
          crowdsecLapiKey: privateKey-foo
          crowdsecLapiHost: crowdsec:8080
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
          enabled: false
          logLevel: DEBUG
          logFormat: common
          LogFilePath: ""
          updateIntervalSeconds: 60
          updateMaxFailure: 0
          crowdsecLapiFailureAction: ban
          streamStartupBlock: true
          defaultDecisionSeconds: 60
          remediationStatusCode: 403
          httpTimeoutSeconds: 10
          crowdsecMode: live
          crowdsecAppsecEnabled: false
          crowdsecAppsecScheme: ""
          crowdsecAppsecHost: crowdsec:7422
          crowdsecAppsecPath: "/"
          crowdsecAppsecFailureAction: ban
          crowdsecAppsecBodyLimit: 10485760
          crowdsecLapiKey: privateKey-foo
          crowdsecLapiScheme: http
          crowdsecLapiHost: crowdsec:8080
          crowdsecLapiPath: "/"
          crowdsecLapiTLSInsecureVerify: false
          crowdsecCapiMachineId: login
          crowdsecCapiPassword: password
          crowdsecCapiScenarios:
            - crowdsecurity/http-path-traversal-probing
            - crowdsecurity/http-xss-probing
            - crowdsecurity/http-generic-bf
          forwardedHeadersTrustedIPs:
            - 10.0.10.23/32
            - 10.0.20.0/24
          clientTrustedIPs:
            - 192.168.1.0/24
          forwardedHeadersCustomName: X-Custom-Header
          decisionScopeHeaders: {}
            # Country: X-IPCountry    # key Country (any case) → ISO country matcher (CDN or geoenrich)
            # AS: CF-ASN             # key AS (any case) → ASN matcher
            # username: X-User       # any other key → trimmed exact match
          remediationHeadersCustomName: cs-remediation
          redisCacheEnabled: false
          redisCacheHost: "redis-primary:6379"
          redisCacheReadHosts:
            - "redis-replica-1:6379"
            - "redis-replica-2:6379"
          redisCachePassword: password
          redisCacheDatabase: "5"
          redisCacheUnreachableBlock: true
          crowdsecLapiTLSCertificateAuthority: |-
            -----BEGIN CERTIFICATE-----
            MIIEBzCCAu+gAwIBAgICEAAwDQYJKoZIhvcNAQELBQAwgZQxCzAJBgNVBAYTAlVT
            ...
            Q0veeNzBQXg1f/JxfeA39IDIX1kiCf71tGlT
            -----END CERTIFICATE-----
          crowdsecLapiTLSCertificateBouncer: |-
            -----BEGIN CERTIFICATE-----
            MIIEHjCCAwagAwIBAgIUOBTs1eqkaAUcPplztUr2xRapvNAwDQYJKoZIhvcNAQEL
            ...
            RaXAnYYUVRblS1jmePemh388hFxbmrpG2pITx8B5FMULqHoj11o2Rl0gSV6tHIHz
            N2U=
            -----END CERTIFICATE-----
          crowdsecLapiTLSCertificateBouncerKey: |-
            -----BEGIN RSA PRIVATE KEY-----
            MIIEogIBAAKCAQEAtYQnbJqifH+ZymePylDxGGLIuxzcAUU4/ajNj+qRAdI/Ux3d
            ...
            ic5cDRo6/VD3CS3MYzyBcibaGaV34nr0G/pI+KEqkYChzk/PZRA=
            -----END RSA PRIVATE KEY-----
          captchaProvider: hcaptcha
          captchaSiteKey: FIXME
          captchaSecretKey: FIXME
          captchaGateSecret: FIXME
          captchaGracePeriodSeconds: 1800
          captchaFilePath: /captcha.html
          banFilePath: /ban.html
          traceHeadersCustomName: X-Request-ID
          metricsUpdateIntervalSeconds: 600
```

#### Fill variable with value of file

`CrowdsecLapiTlsCertificateBouncerKey`, `CrowdsecLapiTlsCertificateBouncer`, `CrowdsecLapiTlsCertificateAuthority`, `CrowdsecAppsecTlsCertificateAuthority`, `CrowdsecCapiMachineId`, `CrowdsecCapiPassword`, `CrowdsecLapiKey`, `CrowdsecAppsecKey`, `CaptchaSiteKey`, `CaptchaSecretKey`, `CaptchaGateSecret` and `RedisCachePassword` can be provided with the content as raw or through a file path that Traefik can read.  
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
    - "traefik.http.middlewares.crowdsec.plugin.bouncer.crowdseclapikey=FIXME-LAPI-KEY"
    - "traefik.http.middlewares.crowdsec.plugin.bouncer.crowdseclapischeme=http"
    - "traefik.http.middlewares.crowdsec.plugin.bouncer.crowdseclapihost=crowdsec:8080"
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

Set `crowdsecLapiScheme` to `https`. The plugin then validates Crowdsec's server certificate. Three options:

- **Publicly trusted certificate** (e.g. Let's Encrypt behind a reverse proxy): leave `crowdsecLapiTLSCertificateAuthority` empty and `crowdsecLapiTLSInsecureVerify` `false`. The plugin falls back to the host's system trust store (the `traefik` image ships `ca-certificates`).
- **Private/self-signed CA**: set `crowdsecLapiTLSCertificateAuthority` (or `…File`) to the PEM-encoded CA that signed Crowdsec's server cert.
- **Skip verification entirely** (not recommended for production): set `crowdsecLapiTLSInsecureVerify` to `true`.

Crowdsec must be listening in HTTPS for this to work.
Please see the [tls-auth example](examples/tls-auth/README.md) or the official documentation: [docs.crowdsec.net/docs/local_api/tls_auth/](https://docs.crowdsec.net/docs/local_api/tls_auth/)

#### Use HTTPS to communicate with the Appsec

Set `crowdsecAppsecScheme` to `https`. Same three options as for the LAPI, prefixed `crowdsecAppsec…` instead of `crowdsecLapi…`: empty CA + secure verify falls back to the system trust store, a custom CA pins to your private PKI, and `crowdsecAppsecTLSInsecureVerify=true` skips verification altogether.

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
This works once you have generated and filled your _LAPI-KEY_ (crowdsecLapiKey), if not read above for informations.

```bash
docker compose -f docker-compose.local.yml up -d
```

Equivalent to

```bash
make run_local
```

### About

This plugin is a fork of [maxlerebourg/crowdsec-bouncer-traefik-plugin](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin).

