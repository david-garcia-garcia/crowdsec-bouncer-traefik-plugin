# Explore
IssueKey: 2026-09-06-upstream-388-split-appsec-timeout

## Concepts

One Traefik plugin config field, `HTTPTimeoutSeconds` (default 10), is multiplied by `time.Second` for three HTTP clients: LAPI (`pkg/lapi/client.go`), AppSec (`pkg/appsec/client.go`), and captcha siteverify (`pkg/bouncer/bouncer.go`). Stream LAPI pulls can be megabytes and need a long timeout. AppSec is a per-request round-trip; when the listener is down, every request waits that same timeout before `crowdsecAppsecFailureAction` (passthrough / ban / captcha). Operators who lengthen the LAPI timeout make AppSec outages hang the site.

```
  request
     │
     ├─ LAPI stream/live ── http.Client.Timeout = HTTPTimeoutSeconds * 1s
     │
     └─ AppSec Query ────── http.Client.Timeout = HTTPTimeoutSeconds * 1s  ← same knob
              │
              timeout / unreachable → CrowdsecAppsecFailureAction
```

Official CrowdSec bouncer spec already splits these: `lapi_timeout` vs `appsec_timeout` (AppSec default 200ms). Nginx has `APPSEC_*_TIMEOUT`. This plugin does not. README already describes `HTTPTimeoutSeconds` as LAPI-only; AppSec still uses it.

AppSec reclaim identity (`pkg/appsec/session.go`) hashes `HTTPTimeoutSeconds`. Two routers that share AppSec URL+key+TLS but differ only in LAPI timeout already get two AppSec clients. Captcha timeout is out of scope of the original ticket; the human later required a captcha knob too.

## Decisions

- **Keep `HTTPTimeoutSeconds` as the public default.** Do not rename it. It remains the fallback for the three client knobs when those are `0` or omitted. README says it is the default for the other three knobs.
- **Three inheriting second knobs.** Public fields `CrowdsecLapiHTTPTimeoutSeconds` (`crowdsecLapiHttpTimeoutSeconds`), `CrowdsecAppsecHTTPTimeoutSeconds` (`crowdsecAppsecHttpTimeoutSeconds`), and `CaptchaSiteverifyHTTPTimeoutSeconds` (`captchaSiteverifyHttpTimeoutSeconds`). Zero / omit inherits `HTTPTimeoutSeconds`. A positive value is that many seconds. Negative is invalid at `ValidateParams`. Owner of the inherit rule: `effectiveHTTPTimeoutSeconds` plus `EffectiveLapiHTTPTimeout`, `EffectiveAppsecHTTPTimeout`, and `EffectiveCaptchaSiteverifyHTTPTimeout`. Do not keep `CrowdsecAppsecTimeoutMilliseconds`.
- **Default stays inherit, not CrowdSec spec 200ms.** Ticket asked for default = `HTTPTimeoutSeconds` when unset. Changing AppSec to 200ms would shorten every existing AppSec deployment without an operator opt-in. Seconds cannot represent 200ms; operators who want a short hang set `crowdsecAppsecHttpTimeoutSeconds: 1` with `crowdsecAppsecFailureAction: passthrough`.
- **Reclaim identity hashes the effective duration, not the raw fallback.** AppSec identity stores effective AppSec seconds. LAPI identity and stream settings store effective LAPI seconds. Same effective timeout → same client even when one router inherited 10s and another set the override to 10. Captcha siteverify is per-bouncer, not a reclaim identity.
- **Fail-open is already `CrowdsecAppsecFailureAction`.** Timeout is a transport error on `http.Client.Do`; `Query` already maps that to passthrough / ban / captcha. This change only makes the wait short. Do not add a second fail-open knob.
- **Tests are unit, not e2e.** Prove inherit vs override in configuration for all three knobs; prove `appsec.New` Timeout with a hanging httptest server + passthrough returns allow in well under the fallback timeout; prove identity keys match on equal effective duration. Real/mock e2e stacks keep `httpTimeoutSeconds: 30` and do not need a hanging AppSec appliance.

## Open questions

- Q: Public JSON name — ticket suggested `AppsecTimeoutSeconds`; existing AppSec keys are `CrowdsecAppsec*`; milliseconds vs float seconds?
  Decision: resolved — `crowdsecLapiHttpTimeoutSeconds`, `crowdsecAppsecHttpTimeoutSeconds`, `captchaSiteverifyHttpTimeoutSeconds`; `httpTimeoutSeconds` stays as the default. Seconds, not milliseconds.
  By: implement

- Q: Should the AppSec default be CrowdSec spec 200ms instead of inherit?
  Decision: resolved — inherit for backward compatibility. Unit is seconds, so the short recommended hang is 1s, not 200ms.
  By: implement

- Q: What does AppSec reclaim identity hash after the split?
  Decision: resolved — the effective AppSec timeout in seconds. LAPI identity hashes the effective LAPI timeout.
  By: implement

- Q: Split captcha siteverify timeout too?
  Decision: resolved — yes; `CaptchaSiteverifyHTTPTimeoutSeconds` inherits `HTTPTimeoutSeconds`.
  By: implement

- Q: Add an e2e scenario with an unreachable AppSec listener?
  Decision: assumed — no; hanging AppSec plus elapsed-time assertion belongs in `pkg/appsec` unit tests. Existing e2e AppSec paths stay healthy-listener coverage.
  By: explore
