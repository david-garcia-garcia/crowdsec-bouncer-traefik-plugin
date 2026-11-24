[Documentation](README.md) › Configuration

# Configuration reference

Every setting of the plugin, grouped by what it configures. Use your editor's search or the outline button at the top of this page on GitHub to jump to a setting.

- [Declare the plugin](#declare-the-plugin)
- [Use it in a middleware](#use-it-in-a-middleware)
- [Settings](#settings)
  - [Connections and sharing](#connections-and-sharing)
  - [Request handling](#request-handling)
  - [LAPI](#lapi)
  - [Redis cache](#redis-cache)
  - [AppSec](#appsec)
  - [ModSecurity](#modsecurity)
  - [Rate limit](#rate-limit)
  - [Captcha](#captcha)
  - [Logging](#logging)
- [Read a value from a file](#read-a-value-from-a-file)

## Declare the plugin

The Traefik static configuration declares the plugin, and the dynamic configuration uses it in a middleware.

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
# relative to the Traefik working directory (see Local mode in development.md).

experimental:
  localPlugins:
    bouncer:
      moduleName: github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin
```

Both load the plugin through Yaegi. For production, compile it into Traefik instead (see the warning in the [README](../README.md)). Local plugin layout: [Local mode](development.md#local-mode).

If you also load the original plugin (`github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin`) as `bouncer`, register this one under another name, for example `crowdsec`, and use `plugin.crowdsec` in the dynamic configuration. The examples in this repository use `bouncer`.

## Use it in a middleware

> You don't need to copy all these settings, only the ones you want to use.
> See the [examples](README.md#examples) for advanced usage.

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

<details>
<summary>Full dynamic configuration, with every setting</summary>

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
          bouncerLapiRedisFailureAction: ban
          bouncerOriginBasedDecisionRemap:
            CAPI:
              ban: captcha
            lists:firehol_level1:
              ban: captcha
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
          logFormat: common
          logLevel: DEBUG
          rateLimitAlgorithm: slidingWindow
          rateLimitBuckets:
            - name: login
              method: "^POST$"
              path: "^/login$"
              requests: 5
              window: 1m
              key:
                - from: ip
          rateLimitEnabled: false
          rateLimitFailureAction: passthrough
          rateLimitInstanceName: ""
          rateLimitRedisDatabase: ""
          rateLimitRedisHost: "redis-primary:6379"
          rateLimitRedisPassword: password
          rateLimitResponseHeaders: true
          rateLimitStatusCode: 429
          rateLimitStore: redis
          rateLimitSyncRate: 200ms
          reclaimGraceSeconds: 30
```

</details>

> [!WARNING]
> AppSec only receives the first 10 MB of a request body by default ([`appsecBodyLimit`](#appsecbodylimit)).

## Settings

Names are written as in YAML. In Docker labels, use the same names (`traefik.http.middlewares.<name>.plugin.bouncer.lapiKey=...`).

Secrets and certificates can also be read from a file: add `File` to the name (`lapiKey` → `lapiKeyFile`). If both are set, the file wins. See [Read a value from a file](#read-a-value-from-a-file).

### Connections and sharing

Which connections this middleware opens, and under which name it shares or reuses them. See [Middleware architecture](middleware-architecture.md).

#### `bouncerEnabled`

`bool` · default `false`

This middleware checks the requests of its router. When `false`, every request is let through (connections this middleware owns are still shared with others).

#### `lapiEnabled`

`bool` · default `false`

This middleware connects to LAPI and shares the connection as `lapiInstanceName`.

#### `lapiInstanceName`

`string` · default the middleware name

Name under which the LAPI connection is shared, or which one to use. See [Middleware architecture](middleware-architecture.md).

#### `appsecEnabled`

`bool` · default `false`

This middleware connects to AppSec and shares the connection as `appsecInstanceName`. AppSec checks every request that passed the decision check, whatever the LAPI mode.

#### `appsecInstanceName`

`string` · default the middleware name

Name under which the AppSec connection is shared, or which one to use. See [Middleware architecture](middleware-architecture.md).

#### `captchaEnabled`

`bool` · default `false`

This middleware sets up the captcha provider and shares it as `captchaInstanceName`. Required to serve captchas; `captchaProvider` alone is not enough.

#### `captchaInstanceName`

`string` · default the middleware name

Name under which the captcha provider is shared, or which one to use. See [Middleware architecture](middleware-architecture.md).

#### `modsecEnabled`

`bool` · default `false`

This middleware connects to the ModSecurity CRS sidecar and shares the connection as `modsecInstanceName`. See [ModSecurity (OWASP CRS)](modsecurity.md).

#### `modsecInstanceName`

`string` · default the middleware name when it connects

Name under which the sidecar connection is shared, or which one to use. See [Middleware architecture](middleware-architecture.md).

#### `rateLimitEnabled`

`bool` · default `false`

Open the rate-limit Redis connection and share it, with `rateLimitBuckets` and the rest of the policy, as `rateLimitInstanceName`. With `bouncerEnabled` and no `rateLimitInstanceName`, the middleware also applies it to its own router. When `false`, the `rateLimit*` settings other than `rateLimitInstanceName` are not read or checked.

#### `rateLimitInstanceName`

`string` · default the middleware name when `rateLimitEnabled`

On the middleware with `rateLimitEnabled`: the name its policy is shared as. On a middleware with `bouncerEnabled`: the policy this router applies, counted under this middleware's name. A middleware with neither `bouncerEnabled` nor `rateLimitEnabled` fails at startup when it sets it. See [Limit how often a client calls a route](rate-limit.md).

#### `reclaimGraceSeconds`

`int64` · default `30`

How long a LAPI, AppSec, ModSec, or rate-limit Redis connection stays open after no middleware uses it, so a Traefik config reload can reuse it instead of reconnecting. `0` closes it immediately. Only the first value loaded in the Traefik process applies.

### Request handling

What this router does with each request. These settings are per router, even when the connection is shared.

#### `bouncerActionRules`

`[]object` · default `[]`

Rules that, for matching requests, skip checks or force a ban or captcha. Each rule has a unique `name` (no `:`), conditions, and an `action` list.

- Conditions (all optional, all must match): `method`, `path`, `host`, `headers`, `cookies`. Values are regular expressions matched anywhere in the value, so anchor them (`^/health$`). `method` accepts a leading `!` to negate (`!POST`). An empty header or cookie pattern means "is present". A rule must have at least one condition.
- Actions: `bypass` (skip LAPI, AppSec, and ModSec), `bypassLapi`, `bypassAppsec`, `bypassModsec`, `bypassCaptcha`, `bypassRateLimit` (skip only the [rate limit](rate-limit.md); `bypass` does not skip it), `captcha`, `ban`. `ban` must be the only action of its rule. `captcha` and `bypassCaptcha` cannot share a rule.
- Every matching rule applies. A `ban` applies immediately. A `captcha` is shown unless CrowdSec bans the client anyway.
- A `bypass`, `bypassLapi`, `bypassAppsec`, `bypassModsec` or `bypassRateLimit` rule with a `path` only skips checks when the path can be read one way. If the request path has percent-encoding (`%2F`, `%20`...), `;`, `\`, `*`, or `.`, `..` or empty segments, the rule still applies its `captcha` but skips nothing. Some backends read such paths differently: Java servers read `/health/..;/admin` as `/admin`. Anchoring the pattern does not prevent this; this check does.
- `bypass*` rules never skip AppSec under `/crowdsec-internal/challenge/` (see [bot detection](concepts.md#appsec)).
- `bypassCaptcha` skips no check. Where a captcha would be served, the request goes through; bans still apply. It wins over a `captcha` action of another matching rule. Its `path` is matched as written, without the check of the previous point. See [Keep captchas off API routes](how-to/captcha-off-api-routes.md) for where it applies and where it does not.

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

To try the rules out, see [Test a ban or a captcha](how-to/test-ban-or-captcha.md).

#### `bouncerAppsecBackOffAction`

`string` · default `passthrough`

What to do while the AppSec backoff gate skips AppSec (`appsecUnhealthyBackOffPeriodSecs`): `passthrough`, `ban`, or `captcha`. AppSec is not called. Per router: two routers on the same AppSec connection share the gate and can answer differently. Verdict header `ban:appsec-backoff` or `captcha:appsec-backoff`. `captcha` needs a captcha instance on this router. See [When a WAF is down](failure-modes.md#when-a-waf-is-down-failure-action-and-backoff).

#### `bouncerAppsecFailureAction`

`string` · default `passthrough` (was `ban`)

What to do when AppSec cannot give an answer (unreachable, error, or request body cannot be read): `passthrough`, `ban`, or `captcha`. With `passthrough`, a POST, PUT, or PATCH body streamed without a length is sent to AppSec with its headers only. While the backoff gate skips AppSec, [`bouncerAppsecBackOffAction`](#bouncerappsecbackoffaction) applies instead. Set `ban` to keep the earlier default. See [Choose what happens when CrowdSec is down](how-to/crowdsec-down.md).

#### `bouncerBanFilePath`

`string` · default `""`

Path to the ban page. Empty means no page (status code only). Content-Type is inferred from the extension. See [Put a request id on the ban page](how-to/request-id-on-ban-page.md) for the template fields.

#### `bouncerClientTrustedIps`

`[]string` · default `[]`

Client IPs or ranges that skip all checks, the rate limit, AppSec, and ModSec included (LAN, VPN). See [Let a LAN or VPN through](how-to/trusted-ips.md).

#### `bouncerDecisionScopeHeaders`

`map[string]string` · default `{}`

Maps a CrowdSec scope (country, AS, or any custom one) to the request header holding its value. See [Decisions](concepts.md#decisions).

#### `bouncerForwardedHeadersCustomName`

`string` · default `"X-Forwarded-For"`

Header holding the real client IP. Only read when the connection comes from an IP in `bouncerForwardedHeadersTrustedIps`. For `X-Forwarded-For`, trusted proxy IPs are skipped from right to left and the first other address is used. Use `X-Real-Ip` only if your front proxy (e.g. nginx or HAProxy) sets it: Traefik fills it in with the connecting IP when missing, so behind Cloudflare it would hold Cloudflare's address. Behind Cloudflare, use `CF-Connecting-IP`.

#### `bouncerForwardedHeadersInsecure`

`bool` · default `false`

Trust the header from any connection, as a single address. Only safe when Traefik's entrypoint already restricts forwarded headers with `forwardedHeaders.trustedIPs`. Otherwise any visitor can choose the IP the plugin checks.

#### `bouncerForwardedHeadersTrustedIps`

`[]string` · default `[]`

IPs or ranges of the proxies in front of Traefik (for example Cloudflare's ranges). The forwarded header is only used when the connection comes from one of them; when empty, the connecting IP is used. Do not use a catch-all such as `0.0.0.0/0`: every address in the header is then treated as a proxy and the plugin silently falls back to the connecting IP. On a private network you can list private ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), as long as real clients are not in them. See [Remediate the visitor, not the proxy](how-to/behind-proxy.md).

#### `bouncerLapiBackOffAction`

`string` · default `ban`

What to do in `live` and `none` while the LAPI backoff gate skips LAPI (`lapiUnhealthyBackOffPeriodSecs`): `ban`, `passthrough`, or `captcha`. LAPI is not called and nothing is cached. Per router. Verdict header `ban:lapi-backoff` or `captcha:lapi-backoff`. Ignored in `stream` and `alone`. A router with `bouncerLapiFailureAction: passthrough` and this default logs a WARN at startup: set this to `passthrough` too to let requests through for the whole outage. See [LAPI](failure-modes.md#lapi).

#### `bouncerLapiFailureAction`

`string` · default `ban`

What to do when LAPI cannot give an answer: `ban`, `passthrough`, or `captcha`. In `live` and `none`, this also applies when a country, AS, or other header-scope lookup fails, and [`bouncerLapiBackOffAction`](#bouncerlapibackoffaction) applies instead while the backoff gate skips LAPI. See [Choose what happens when CrowdSec is down](how-to/crowdsec-down.md).

#### `bouncerModsecBackOffAction`

`string` · default `passthrough`

What to do while the ModSec backoff gate skips the sidecar (`modsecUnhealthyBackOffPeriodSecs`): `passthrough`, `ban`, or `captcha`, as for AppSec. The sidecar is not called. Per router. Verdict header `ban:modsec-backoff` or `captcha:modsec-backoff`. See [When a WAF is down](failure-modes.md#when-a-waf-is-down-failure-action-and-backoff).

#### `bouncerLapiRedisFailureAction`

`string` · default `ban`

What to do when the LAPI Redis cache cannot be read: `ban`, `passthrough`, or `captcha`. Every failure counts: Redis cannot be reached, answers in more than about 1 second, or answers with an error (TLS rejected, wrong or missing password). `passthrough` skips the LAPI check and the request goes on to the next checks. `bouncerLapiFailureAction` does not apply. See [The LAPI Redis cache](failure-modes.md#the-lapi-redis-cache).

#### `bouncerModsecFailureAction`

`string` · default `passthrough`

What to do when the ModSecurity sidecar gives no verdict (5xx, timeout, unreachable, or no connection published yet): `passthrough`, `ban`, or `captcha`, as for AppSec. A POST, PUT, or PATCH body streamed without a length is inspected on its headers only with `passthrough`, and gets this action otherwise. While the backoff gate skips the sidecar, [`bouncerModsecBackOffAction`](#bouncermodsecbackoffaction) applies instead. A 3xx or 4xx from the sidecar is a block, not a failure. See [When a WAF is down](failure-modes.md#when-a-waf-is-down-failure-action-and-backoff).

#### `bouncerOriginBasedDecisionRemap`

`map[string]map[string]string` · default `{}`

Turn bans or captchas from specific origins into a captcha or a pass on this router. See [Show a community ban as a captcha](how-to/community-ban-as-captcha.md).

#### `bouncerRemediationHeadersCustomName`

`string` · default `""`

Response header that tells why a request was blocked or challenged. Empty disables it. See [See the verdict in access logs](how-to/verdict-in-access-logs.md).

#### `bouncerRemediationStatusCode`

`int` · default `403`

HTTP status for a ban from the LAPI, a failure action, or an action rule. It does not set the status of an AppSec ban. An AppSec ban is answered with the `http_status` of the AppSec response when it is between 200 and 599. CrowdSec sets that value to 403 unless `user_blocked_http_code` or [SetReturnCode()](https://docs.crowdsec.net/docs/appsec/hooks/#on_match) changes it, and to 429 for a `RateLimit()` block (CrowdSec 1.8.2+). To change the status of AppSec bans, set `user_blocked_http_code` in the CrowdSec appsec-config. This value applies only when the AppSec response has no valid `http_status`. A 204 or 304 status is sent without the ban page.

#### `bouncerTraceHeadersCustomName`

`string` · default `""`

Request header copied into the ban page as `{{ .TraceID }}`. See [Put a request id on the ban page](how-to/request-id-on-ban-page.md).

### LAPI

How the middleware that connects to LAPI (`lapiEnabled: true`) reaches it and keeps decisions. See [LAPI modes](concepts.md#lapi-modes) and [Connect to CrowdSec](connect-to-crowdsec.md).

#### `lapiHost`

`string` · default `"crowdsec:8080"`

LAPI host and port.

#### `lapiKey`

`string` · default `""`

Bouncer API key for LAPI. See [Generate a LAPI key](connect-to-crowdsec.md#generate-a-lapi-key).

#### `lapiMode`

`string` · default `live`

`stream`, `live`, `none`, or `alone`. See [LAPI modes](concepts.md#lapi-modes).

#### `lapiPath`

`string` · default `"/"`

Path appended to `lapiHost`. Ignored in `alone`.

#### `lapiScheme`

`string` · default `http`

`http` or `https`. See [Use HTTPS to communicate with LAPI](connect-to-crowdsec.md#use-https-to-communicate-with-lapi).

#### `lapiHttpTimeoutSeconds`

`int64` · default `10`

Timeout in seconds when contacting LAPI. Must be at least `1`.

#### `lapiUpdateIntervalSeconds`

`int64` · default `60`

Seconds between decision refreshes in `stream`. Fixed to `7200` in `alone`.

#### `lapiUpdateMaxFailure`

`int64` · default `0`

`stream` and `alone` only. Number of failed refreshes tolerated before `bouncerLapiFailureAction` applies to clients without a known decision. `0` reacts on the first failure; `-1` never. Known decisions keep applying. In `live` and `none` it has no effect: `bouncerLapiFailureAction` applies on the first failed lookup, then the backoff gate (`lapiUnhealthyBackOffPeriodSecs`) takes over. To let traffic through while LAPI is down there, use `bouncerLapiFailureAction: passthrough` and `bouncerLapiBackOffAction: passthrough`. See [Choose what happens when CrowdSec is down](how-to/crowdsec-down.md).

#### `lapiDefaultDecisionSeconds`

`int64` · default `60`

`live` only. How long a LAPI answer is cached, at most.

#### `lapiUnhealthyBackOffPeriodSecs`

`int64` · default `10`

`live` and `none` only. Cooldown in seconds of the LAPI backoff gate. After 5 live lookups in a row that LAPI does not answer (timeout, refused connection, 5xx, or 429; a 401 or 403 does not count), LAPI is not called for this long and lookups get each router's [`bouncerLapiBackOffAction`](#bouncerlapibackoffaction) (default `ban`) at once, instead of waiting up to `lapiHttpTimeoutSeconds` each. `0` turns the gate off: every lookup calls LAPI, as in earlier versions. Must be `0` or more. Set on the middleware that connects to LAPI; ignored in `stream` and `alone`. See [LAPI](failure-modes.md#lapi).

#### `lapiStreamScopes`

`[]string` · default empty

Extra decision scopes to download in `stream` (`country`, `as`, …). IP and range decisions are always included. Set it on the middleware that connects to LAPI. See [Match a country or an ASN](how-to/country-or-asn.md).

#### `lapiMetricsUpdateIntervalSeconds`

`int64` · default `600`

Seconds between metrics reports to LAPI. `0` disables metrics. See [LAPI metrics reporting](concepts.md#lapi-metrics-reporting).

#### `lapiTlsCertificateAuthority`

`string` · default `""`

PEM CA that signed LAPI's certificate. Empty uses the system trust store.

#### `lapiTlsClientCertificate`

`string` · default `""`

PEM client certificate of the bouncer.

#### `lapiTlsClientKey`

`string` · default `""`

PEM client private key of the bouncer.

#### `lapiTlsInsecureVerify`

`bool` · default `false`

Do not verify LAPI's certificate. Not for production.

#### `lapiCapiMachineId`

`string` · no default

`alone` only. CAPI login.

#### `lapiCapiPassword`

`string` · no default

`alone` only. CAPI password.

#### `lapiCapiScenarios`

`[]string` · no default

`alone` only. CAPI scenarios.

### Redis cache

Only useful in `live` mode with several Traefik replicas. See [Cache](concepts.md#cache) and [examples/redis-cache](../examples/redis-cache/README.md).

#### `lapiRedisEnabled`

`bool` · default `false`

Use Redis instead of memory for the cache.

#### `lapiRedisHost`

`string` · default `"redis:6379"`

Redis primary, `host:port`.

#### `lapiRedisReadHosts`

`[]string` · default `[]`

Redis replicas for reads, used in turn. Defaults to `lapiRedisHost`. Reads do not fall back to the primary, so an outage of the replicas blocks requests (see [`bouncerLapiRedisFailureAction`](#bouncerlapiredisfailureaction)) even if the primary is up.

#### `lapiRedisPassword`

`string` · default `""`

Redis password.

#### `lapiRedisDatabase`

`string` · default `""`

Redis database.

### AppSec

How the middleware that connects to AppSec (`appsecEnabled: true`) reaches it. See [AppSec](concepts.md#appsec).

#### `appsecHost`

`string` · default `"crowdsec:7422"`

AppSec host and port.

#### `appsecKey`

`string` · default `""`

AppSec API key. Defaults to `lapiKey`.

#### `appsecPath`

`string` · default `"/"`

Path appended to `appsecHost`.

#### `appsecScheme`

`string` · default `""`

`http` or `https`. Defaults to `lapiScheme`. See [Use HTTPS to communicate with AppSec](connect-to-crowdsec.md#use-https-to-communicate-with-appsec).

#### `appsecHttpTimeoutSeconds`

`int64` · default `10`

Timeout in seconds when contacting AppSec. Must be at least `1`. For example, `1` with `bouncerAppsecFailureAction: passthrough` lets requests through after one second if AppSec hangs.

#### `appsecBodyLimit`

`int64` · default `10485760` (10 MB)

Send at most this many bytes of the request body to AppSec. `0` means no limit: the whole body is sent. Only POST, PUT, PATCH, and DELETE bodies are sent. `/crowdsec-internal/challenge/submit` must reach AppSec with the full form. The default 10MB is enough. A smaller positive limit cuts the proof short.

#### `appsecTlsCertificateAuthority`

`string` · default `""`

PEM CA that signed AppSec's certificate. Empty uses the system trust store.

#### `appsecTlsClientCertificate`

`string` · default `""`

PEM client certificate presented to AppSec. Used with `appsecTlsClientKey`.

#### `appsecTlsClientKey`

`string` · default `""`

PEM client private key presented to AppSec.

#### `appsecTlsInsecureVerify`

`bool` · default `false`

Do not verify AppSec's certificate. Not for production.

#### `appsecUnhealthyBackOffPeriodSecs`

`int64` · default `10` (was `30`)

Cooldown in seconds of the AppSec backoff gate. After 5 AppSec failures in a row (or failures above about 30% of requests), AppSec is skipped for this long: requests get each router's [`bouncerAppsecBackOffAction`](#bouncerappsecbackoffaction) (default `passthrough`), not `bouncerAppsecFailureAction`. `0` turns the gate off, so every request calls AppSec and every failure gets the failure action. Set on the middleware that connects to AppSec. See [When a WAF is down](failure-modes.md#when-a-waf-is-down-failure-action-and-backoff).

### ModSecurity

How the middleware that connects to the sidecar (`modsecEnabled: true`) reaches it. The failure action is per router: [`bouncerModsecFailureAction`](#bouncermodsecfailureaction). See [ModSecurity (OWASP CRS)](modsecurity.md).

#### `modsecUrl`

`string` · no default

Absolute `http` or `https` URL of the inspect-only sidecar, for example `http://waf:8080`. Required when `modsecEnabled` is true. The request path and query are appended to it, so it must not have a query or fragment of its own.

#### `modsecHttpTimeoutSeconds`

`int64` · default `10`

Timeout in seconds for one sidecar call. Must be at least `1`. CRS can take seconds on a large body; a timeout is a failure, not an allow.

#### `modsecBodyLimit`

`int64` · default `8388608` (8 MiB)

Largest request body sent to the ModSecurity sidecar. A larger body gets HTTP 413 and the sidecar is not called. The whole body is held in memory, so there is no unlimited value: it must be at least `1`. Keep it at or below the sidecar's `MODSEC_REQ_BODY_NOFILES_LIMIT` (128 KiB in the image by default), or the sidecar answers 413 itself and the visitor gets that as a block.

#### `modsecUnhealthyBackOffPeriodSecs`

`int64` · default `10` (was `0`, off)

Cooldown in seconds of the ModSec backoff gate, same rule as `appsecUnhealthyBackOffPeriodSecs`: after 5 sidecar failures in a row, the sidecar is skipped for this long and requests get each router's [`bouncerModsecBackOffAction`](#bouncermodsecbackoffaction) (default `passthrough`), not `bouncerModsecFailureAction`. `0` turns the gate off, as before. Set on the middleware that connects to the sidecar.

### Rate limit

The rate-limit policy and its Redis connection. Every setting below is read only on the middleware with `rateLimitEnabled: true`; routers that apply the policy name it with [`rateLimitInstanceName`](#ratelimitinstancename). See [Limit how often a client calls a route](rate-limit.md).

#### `rateLimitBuckets`

`[]object` · default `[]`

The rate-limit buckets, checked in list order. Required when `rateLimitEnabled` is `true`. Each bucket has a unique `name` (no `:`), optional conditions (`method`, `path`, `host`, `headers`, `cookies`, as in `bouncerActionRules`; none means every request), `key` (list of `from`: `ip`, `header`, `cookie`, `query`, `host`, `path`, `method`, with `name` for `header`/`cookie`/`query`, optional `pattern` with a capture group, and `ipv4Prefix` / `ipv6Prefix` for `ip`), `requests` (at least 1), `window` (a duration in whole seconds, at least `1s`), `burst` (only with `rateLimitAlgorithm: tokenBucket`, at least 1, default `requests`), `action` (`ratelimit` by default, `captcha`, or `log`; `deny` fails at startup), and `final` (default `false`). `algorithm` on a bucket fails at startup: use `rateLimitAlgorithm`. Read only on the middleware with `rateLimitEnabled`. See [Limit how often a client calls a route](rate-limit.md).

#### `rateLimitAlgorithm`

`string` · default `slidingWindow`

How every bucket of the policy counts: `slidingWindow` (`requests` per rolling `window`; a request over the limit still counts) or `tokenBucket` (refill `requests` per `window`, up to `burst` at once; a request over the limit takes no token). Changing it starts every bucket from zero. Read only on the middleware with `rateLimitEnabled`. See [Limit how often a client calls a route](rate-limit.md).

#### `rateLimitFailureAction`

`string` · default `passthrough`

What to do when the rate-limit Redis cannot answer: `passthrough`, `ban`, or `captcha` (the captcha of each router that applies the policy; a router without one serves `ban:captcha-downgrade`). Read only on the middleware with `rateLimitEnabled`. With the sliding window and the default buffered `rateLimitSyncRate`, an unreachable Redis does not trigger it: each replica keeps its own count. It applies with `rateLimitSyncRate: 0`, always with `rateLimitAlgorithm: tokenBucket`, and in every mode to a bucket reached after the 250ms the rate limit may spend on Redis.

#### `rateLimitStatusCode`

`int` · default `429`

HTTP status of a `ratelimit` answer. Separate from `bouncerRemediationStatusCode`. Read only on the middleware with `rateLimitEnabled`.

#### `rateLimitResponseHeaders`

`bool` · default `true`

Send `Retry-After` on a `ratelimit` answer. Read only on the middleware with `rateLimitEnabled`.

#### `rateLimitSyncRate`

`string` · default `200ms`

How often each replica writes its local sliding-window counts to Redis. `0` writes every hit before answering (exact counts). A positive value below `20ms` is treated as `20ms`. Not read with `rateLimitAlgorithm: tokenBucket`, which calls Redis for every counted bucket. Read only on the middleware with `rateLimitEnabled`.

#### `rateLimitStore`

`string` · default `redis`

Where counters are kept. Only `redis` in this version.

#### `rateLimitRedisHost`

`string` · default `redis:6379`

Redis (or Dragonfly) `host:port` that holds the rate-limit counters. It does not fall back to `lapiRedisHost`.

#### `rateLimitRedisPassword`

`string` · default `""`

Password for the rate-limit Redis. `rateLimitRedisPasswordFile` reads it from a file.

#### `rateLimitRedisDatabase`

`string` · default `""`

Redis database number for the rate-limit counters.

### Captcha

How the middleware that sets up the captcha (`captchaEnabled: true`) talks to the provider and remembers solved captchas. See [Remediation](concepts.md#remediation) and [examples/captcha](../examples/captcha/README.md).

#### `captchaProvider`

`string` · no default

`hcaptcha`, `recaptcha`, `recaptcha-enterprise`, `turnstile`, `eucaptcha`, or `custom`.

#### `captchaSiteKey`

`string` · no default

Site key from the captcha provider.

#### `captchaSecretKey`

`string` · no default

Secret key from the captcha provider. Required for every provider except `recaptcha-enterprise`.

#### `captchaGateSecret`

`string` · no default

Secret used to sign the cookie that remembers a solved captcha. Required when captcha is enabled. Use a long random value; it is not the provider's secret key.

#### `captchaGateBindIp`

`bool` · default `true`

Tie a solved captcha to the visitor's IP. When `false`, the cookie alone is enough, even if the visitor's IP changes.

#### `captchaGracePeriodSeconds`

`int64` · default `86400` (24 hours)

How long a solved captcha is valid. After that, the visitor is challenged again if CrowdSec still has a decision for them.

#### `captchaFilePath`

`string` · default `/captcha.html`

Path to the captcha page template. Content-Type is inferred from the extension.

A custom template must put this hidden field inside its challenge form:

```html
<input type="hidden" name="crowdsec_captcha_challenge" value="v1">
```

The plugin uses it to recognise a leftover challenge form. Example: the visitor has the captcha open in two tabs, solves it in one, then submits the other. With the field, that second POST is redirected and never reaches your application. Without it, the captcha still works, but the second POST is forwarded to the backend (a route that only accepts GET answers 405). The provider's response field (`g-recaptcha-response`, `h-captcha-response`, ...) is not used for this, because your application's own forms may embed the same widget. When the loaded template does not contain the field, the plugin logs `crowdsec captcha template missing challenge marker` at startup.

#### `captchaSiteverifyHttpTimeoutSeconds`

`int64` · default `10`

Timeout in seconds when validating a captcha with the provider. Must be at least `1`.

#### `captchaCustomJsUrl`

`string` · no default

`custom` only. Script URL that loads the widget (hCaptcha: `https://hcaptcha.com/1/api.js`). If it is served from the protected router, visitors who must solve a captcha are allowed to request it.

#### `captchaCustomKey`

`string` · no default

`custom` only. CSS class of the captcha div (hCaptcha: `h-captcha`).

#### `captchaCustomResponse`

`string` · no default

`custom` only. Name of the form field holding the captcha answer (hCaptcha: `h-captcha-response`).

#### `captchaCustomValidateUrl`

`string` · no default

`custom` only. URL that validates the answer (hCaptcha: `https://api.hcaptcha.com/siteverify`).

#### `captchaCustomValidateBody`

`string` · default `""`

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

#### `captchaCustomChallengeUrl`

`string` · default `""`

`custom` only. Challenge URL of the widget (Wicketkeeper: `http://captcha.localhost:8000/v0/challenge`), available in the template as `{{ .ChallengeURL }}`. Visitors who must solve a captcha are allowed to request this exact path. See [examples/custom-captcha](../examples/custom-captcha/README.md).

#### `captchaEnterpriseProjectId`

`string` · no default

`recaptcha-enterprise` only. Google Cloud project id. Required.

#### `captchaEnterpriseApiKey`

`string` · no default

`recaptcha-enterprise` only. Google Cloud API key. Required.

#### `captchaEnterpriseKeyType`

`string` · no default

`recaptcha-enterprise` only. `checkbox` or `score`. Required.

#### `captchaEnterpriseAction`

`string` · default `""`

`recaptcha-enterprise` only. Expected action name. Required for `score` keys, optional for `checkbox` keys.

#### `captchaEnterpriseMinScore`

`string` · default `""`

`recaptcha-enterprise` only. Minimum score to pass, greater than `0` and up to `1` (e.g. `"0.5"`). Required for `score` keys, ignored for `checkbox` keys.

### Logging

The plugin writes its logs to stdout, next to Traefik's own. Send them to a file, rotate them, or ship them with Traefik's or the container runtime's log handling (for example the Docker logging driver or journald).

#### `logLevel`

`string` · default `INFO`

`TRACE`, `DEBUG`, `INFO`, `WARN`, or `ERROR`. `TRACE` logs every request; `DEBUG` logs startup, refreshes, and errors.

#### `logFormat`

`string` · default `common`

`common` (text) or `json`.

## Read a value from a file

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
| `rateLimitRedisPassword` | `rateLimitRedisPasswordFile` |
| `appsecKey` | `appsecKeyFile` |
| `appsecTlsCertificateAuthority` | `appsecTlsCertificateAuthorityFile` |
| `appsecTlsClientCertificate` | `appsecTlsClientCertificateFile` |
| `appsecTlsClientKey` | `appsecTlsClientKeyFile` |
| `captchaSiteKey` | `captchaSiteKeyFile` |
| `captchaSecretKey` | `captchaSecretKeyFile` |
| `captchaEnterpriseApiKey` | `captchaEnterpriseApiKeyFile` |
| `captchaGateSecret` | `captchaGateSecretFile` |
