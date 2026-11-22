[Documentation](../README.md) › [How-to](README.md) › Keep captchas off API routes

# Keep captchas off API routes

A captcha is a web page for a person. A script, a mobile app, or another server calling your API cannot solve it. It receives the captcha HTML with HTTP 200 where it expected its API response. This happens, for example, when a CrowdSec `captcha` decision covers a whole network (AS) and your own integration calls the API from an address in that network.

The `bypassCaptcha` action lets matching requests through wherever this router would have served a captcha. Bans still apply.

```yaml
bouncerActionRules:
  - name: api-no-captcha
    path: "^/api/"
    action: [bypassCaptcha]
```

The rule skips no check. The plugin still looks up CrowdSec decisions and still queries AppSec for these requests. Only the captcha answer changes: the request continues to the next check and then to your application. It gets no remediation header and is not counted as dropped.

## Where it applies

On a matching request, each of these lets the request through:

| A captcha would have been served because | Header it would have carried |
| ---------------------------------------- | ---------------------------- |
| A CrowdSec decision of type `captcha` matches the client (its IP, range, country, AS, or a custom scope). | `captcha:lapi`, `captcha:lapi:<origin>` |
| LAPI is unreachable, or decisions could not be refreshed, and `bouncerLapiFailureAction` is `captcha`. | `captcha:lapi-failure`, `captcha:stream-unhealthy` |
| AppSec answered `captcha`. | `captcha:appsec` |
| AppSec is unreachable and `bouncerAppsecFailureAction` is `captcha`. | `captcha:appsec-failure` |
| The ModSecurity sidecar gave no verdict and `bouncerModsecFailureAction` is `captcha`. | `captcha:modsec-failure` |
| Another matching rule has the `captcha` action. | `captcha:rules` |
| A captcha was due and this router has no captcha configured, so a ban would have been served. | `ban:captcha-downgrade` |

## Where it does not apply

These are unchanged on a matching request:

| Case | What happens |
| ---- | ------------ |
| Any ban: a CrowdSec `ban` decision, an AppSec block, a `ban` rule, a failure action `ban`, Redis unreachable. | The request is banned. |
| A ban that `bouncerOriginBasedDecisionRemap` softens to a captcha (`ban: captcha`). | It stays a ban on these requests. Otherwise a ban would end as a pass. A remap `ban: pass` still lets the request through. |
| The AppSec bot-detection challenge (`captcha:challenge`). | It is still served. It is AppSec's own page, not this router's captcha, although its header value starts with `captcha:`. |
| A request the rule does not match. | It gets the captcha as before. |
| A client in `bouncerClientTrustedIps`. | It skips the whole plugin, these rules included. |

`captcha` and `bypassCaptcha` in the same rule are rejected when the configuration loads.

Match on what the client cannot choose for another resource: the path, the host, the method. Do not write a `bypassCaptcha` rule on a header or a cookie the client sets, such as `User-Agent` or `X-Requested-With`. Any visitor could add it and skip the captcha on every page.

## What you give up

On the matching requests a captcha no longer slows anyone down. A client that CrowdSec wanted to challenge can call those routes freely, and during a LAPI, AppSec or ModSecurity outage with failure action `captcha` they are let through as with `passthrough`. Only bans stop a client there. If one known integration is the reason for the rule and it has a fixed address, [`bouncerClientTrustedIps`](trusted-ips.md) for that address is the narrower setting.

## How the path is matched

The `path` pattern runs as written on the path the plugin receives, for every request. The other skip actions (`bypass`, `bypassLapi`, `bypassAppsec`, `bypassModsec`, `bypassRateLimit`) switch themselves off on a path with percent-encoding or other ambiguous characters. `bypassCaptcha` does not, so `/api/items%20x` works. It relies on Traefik having cleaned the path first. Measured on Traefik v3.7.11 and v3.7.19 with the rule above:

| Request sent | Path the plugin and your application receive | Captcha bypassed |
| ------------ | -------------------------------------------- | ---------------- |
| `/api/../admin`, `/api/%2e%2e/admin` | `/admin` | No. Traefik resolved the path before the plugin. |
| `/api/..;/admin` | `/admin` from Traefik v3.7.18. Unchanged on earlier versions. | No from v3.7.18. Yes on earlier versions. |
| `/api/..%2Fadmin`, `/api/..%5Cadmin`, `/api/..%3B/admin`, `/api/%252e%252e/admin` | Unchanged | Yes |
| `/api/..\admin` | `/api/..%5Cadmin`. Traefik encodes the backslash and does not resolve it. | Yes |

The last two rows are the limit. Traefik does not decode `%2F` (`/`), `%5C` (`\`), `%3B` (`;`) or `%25` (`%`) by default, so the request still starts with `/api/` and the rule matches. Your application receives the same encoded path. If it decodes those characters and then resolves `..`, it serves `/admin` to a client that should have seen a captcha. Anchoring the pattern does not prevent this. Bans are not affected: a banned client stays banned on every path.

To close it, make Traefik reject those encoded characters on the entry point. It then answers HTTP 400 before the plugin runs, also for a raw `\`:

```yaml
# Traefik static configuration (CLI flags)
- "--entrypoints.websecure.http.encodedCharacters.allowEncodedSlash=false"
- "--entrypoints.websecure.http.encodedCharacters.allowEncodedBackSlash=false"
- "--entrypoints.websecure.http.encodedCharacters.allowEncodedSemicolon=false"
- "--entrypoints.websecure.http.encodedCharacters.allowEncodedPercent=false"
```

Check first that no legitimate URL of your application uses them, for example an identifier that contains an encoded `/`. See [Request Path](https://doc.traefik.io/traefik/security/request-path/) in the Traefik documentation.
