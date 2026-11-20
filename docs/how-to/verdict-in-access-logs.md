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
