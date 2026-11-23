[Documentation](../README.md) › [How-to](README.md) › See the verdict in access logs

# See the verdict in access logs

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
| `ban:lapi-backoff` | LAPI kept failing, so the backoff gate did not call it (`live` and `none`), and the backoff action is `ban`. |
| `ban:stream-unhealthy` | Decisions could not be refreshed for too long, and the failure action is `ban`. |
| `ban:cache-fail` | The LAPI Redis cache could not be read (see [The LAPI Redis cache](../failure-modes.md#the-lapi-redis-cache)). |
| `ban:appsec` | Blocked by AppSec. |
| `ban:appsec-challenge-empty` | AppSec asked for a bot challenge but sent no page, so a ban was served instead. |
| `ban:appsec-action-empty` | AppSec returned an action this plugin cannot show (for example a custom `SetRemediation("tarpit")`) and sent no page, so a ban was served instead. |
| `ban:appsec-failure` | AppSec was unreachable, and the failure action is `ban`. |
| `ban:appsec-backoff` | AppSec kept failing, so the backoff gate did not call it, and the backoff action is `ban`. |
| `ban:modsec` | Blocked by the ModSecurity CRS sidecar. The visitor got the sidecar's response. |
| `ban:modsec-failure` | The ModSecurity sidecar gave no verdict, and the failure action is `ban`. |
| `ban:modsec-backoff` | The ModSecurity sidecar kept failing, so the backoff gate did not call it, and the backoff action is `ban`. |
| `ban:ratelimit:<bucket>` | A rate-limit bucket with `action: ratelimit` is over its limit, or a bucket with `action: captcha` is and this router has no captcha or a `bypassCaptcha` rule matched. The third field is the bucket name. |
| `ban:ratelimit-failure` | The rate-limit Redis could not answer (see [When Redis is down](../rate-limit.md)), and `rateLimitFailureAction` is `ban`. |
| `ban:captcha-downgrade` | A captcha was due, but this router has no captcha configured, so a ban was served. |
| `captcha:rules` | Captcha from a `bouncerActionRules` rule. |
| `captcha:lapi` / `captcha:lapi:<origin>` | Captcha from a CrowdSec decision. |
| `captcha:lapi-failure` | LAPI was unreachable, and the failure action is `captcha`. |
| `captcha:lapi-backoff` | The LAPI backoff gate did not call LAPI, and the backoff action is `captcha`. |
| `captcha:stream-unhealthy` | Decisions could not be refreshed for too long, and the failure action is `captcha`. |
| `captcha:appsec-failure` | AppSec was unreachable, and the failure action is `captcha`. |
| `captcha:appsec-backoff` | The AppSec backoff gate did not call AppSec, and the backoff action is `captcha`. |
| `captcha:modsec-failure` | The ModSecurity sidecar gave no verdict, and the failure action is `captcha`. |
| `captcha:modsec-backoff` | The ModSec backoff gate did not call the sidecar, and the backoff action is `captcha`. |
| `captcha:ratelimit:<bucket>` | A rate-limit bucket with `action: captcha` is over its limit, and this router served its captcha page. The third field is the bucket name. |
| `captcha:ratelimit` | The rate limit checked a captcha form posted on this router, the answer was wrong, and the captcha page was served again. |
| `captcha:ratelimit-failure` | The rate-limit Redis could not answer (see [When Redis is down](../rate-limit.md)), and `rateLimitFailureAction` is `captcha`. |
| `captcha:appsec` | AppSec asked for a captcha, and this router served its own captcha page. |
| `captcha:challenge` | AppSec served a bot-detection challenge. |
| `captcha:solved` | The visitor just solved the captcha and is being redirected back. |
| `error:client-disconnected` | The client disconnected while AppSec or ModSec was reading the request body. Not a ban. |
| `error:client-body-read` | The request body could not be read whole for AppSec or ModSec while the client was still connected (for example an upload slower than the entry point read timeout). Answered HTTP 400 `Bad Request`. Not a ban. |
| `error:body-read-timeout` | A request body without `Content-Length` did not arrive within `appsecBodyReadTimeoutSeconds` or `modsecBodyReadTimeoutSeconds`. Answered HTTP 400 `Bad Request` whatever the failure action. Not a ban. A gRPC stream or another body that never ends gets this: see [Run streaming request bodies through the WAF legs](streaming-request-bodies.md). |
| `<action>:appsec` | Any other action returned by AppSec. |

Requests that are let through get no header. A client address that cannot be read (`RemoteAddr` is not `host:port`, or the chosen text is not an IP) is HTTP 502 `Bad Gateway`, also with no header.
