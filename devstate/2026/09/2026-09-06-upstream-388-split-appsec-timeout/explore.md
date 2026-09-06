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

AppSec reclaim identity (`pkg/appsec/session.go`) hashes `HTTPTimeoutSeconds`. Two routers that share AppSec URL+key+TLS but differ only in LAPI timeout already get two AppSec clients. Captcha timeout is out of scope.

## Decisions

- **One new AppSec knob, milliseconds, CrowdsecAppsec prefix.** Public field `CrowdsecAppsecTimeoutMilliseconds` (`json:"crowdsecAppsecTimeoutMilliseconds,omitempty"`), `int64`, same shape as the rest of `Config`. Zero / omit inherits `HTTPTimeoutSeconds * time.Second`. A positive value is that many milliseconds. Negative is invalid at `ValidateParams`. Owner of the inherit rule: `configuration.EffectiveAppsecTimeout(*Config) time.Duration`. `appsec.New` and AppSec identity both call it. Do not add `AppsecTimeoutSeconds`, a float seconds field, or a duration string — Traefik plugin config here is int64-with-unit-in-the-name; no floats or pointers exist on `Config`.
- **Default stays inherit, not CrowdSec spec 200ms.** Ticket asked for default = `HTTPTimeoutSeconds` when unset. Changing AppSec to 200ms would shorten every existing AppSec deployment without an operator opt-in. README will say operators who want a short fail-open hang should set `crowdsecAppsecTimeoutMilliseconds: 200` (CrowdSec spec default) together with `crowdsecAppsecFailureAction: passthrough`.
- **LAPI and captcha keep `HTTPTimeoutSeconds`.** Do not add LAPI millisecond config. Do not split captcha siteverify.
- **Reclaim identity hashes the effective AppSec duration, not raw LAPI seconds.** Replace `identity.HTTPTimeoutSeconds` with the resolved millisecond count (or nanoseconds) that `EffectiveAppsecTimeout` produces. Same effective timeout → same AppSec client even when one router inherited 10s and another set `10000`. Different effective timeouts stay isolated. LAPI identity continues to hash `HTTPTimeoutSeconds` unchanged.
- **Fail-open is already `CrowdsecAppsecFailureAction`.** Timeout is a transport error on `http.Client.Do`; `Query` already maps that to passthrough / ban / captcha. This change only makes the wait short. Do not add a second fail-open knob.
- **Tests are unit, not e2e.** Prove inherit vs override in configuration; prove `appsec.New` Timeout with a hanging httptest server + passthrough returns allow in well under the LAPI timeout; prove identity keys match on equal effective duration. Real/mock e2e stacks keep `httpTimeoutSeconds: 30` and do not need a hanging AppSec appliance.

## Open questions

- Q: Public JSON name — ticket suggested `AppsecTimeoutSeconds`; existing AppSec keys are `CrowdsecAppsec*`; milliseconds vs float seconds?
  Decision: assumed — `crowdsecAppsecTimeoutMilliseconds` int64; 0 inherits `HTTPTimeoutSeconds`. One knob, prefix + unit match `CrowdsecAppsecBodyLimit` / `HTTPTimeoutSeconds`.
  By: explore

- Q: Should the AppSec default be CrowdSec spec 200ms instead of inherit?
  Decision: assumed — inherit for backward compatibility. Document 200ms as the recommended short value, do not change CreateConfig defaults.
  By: explore

- Q: What does AppSec reclaim identity hash after the split?
  Decision: assumed — the effective AppSec timeout duration (milliseconds), not `HTTPTimeoutSeconds` and not both raw fields. LAPI identity unchanged.
  By: explore

- Q: Split captcha siteverify timeout too?
  Decision: assumed — no; ticket is AppSec vs LAPI. Captcha stays on `HTTPTimeoutSeconds`.
  By: explore

- Q: Add an e2e scenario with an unreachable AppSec listener?
  Decision: assumed — no; hanging AppSec plus elapsed-time assertion belongs in `pkg/appsec` unit tests. Existing e2e AppSec paths stay healthy-listener coverage.
  By: explore
