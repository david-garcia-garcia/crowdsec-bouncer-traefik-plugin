# Explore
IssueKey: 2026-09-18-alone-mode-skips-appsec-validation

## Concepts

`ValidateParams` runs in `New` before `lapi.Prepare` / `appsec.Prepare`. Alone is a CAPI stream mode: it still OpenStreams and can Open AppSec when `crowdsecAppsecEnabled`. The spec MAY skip LAPI URL, LAPI key, and LAPI TLS after CAPI credentials. It does not MAY-skip AppSec URL, AppSec key-file, or AppSec HTTPS CA.

Current split:

```
ValidateParams
  required / captcha / IPs / redis-password-file / templates
  ┌─ alone ── CAPI machine+password ── (no connection helper)
  └─ else ── validateLapiAndAppsecConnection
                ├─ validateLapiURLAndKeys
                └─ validateAppsecURLKeyAndTLS
  logging
```

`validateAppsecURLKeyAndTLS` is the AppSec owner: effective-scheme URL, `GetVariable("CrowdsecAppsecKey")` (so a set `CrowdsecAppsecKeyFile` must exist), and `validateParamsTLS` when `CrowdsecAppsecScheme == https` and insecure-verify is false. Live/stream/none/appsec always call it. Alone never does. Hunt name `TestHunt_ValidateParams_aloneModeStillRejectsInvalidAppsecCA` is not in the tree.

Ticket Desired gates those checks on `crowdsecAppsecEnabled` or AppSec TLS/key fields. Live/stream have no such gate. Default AppSec host `crowdsec:7422` already passes the URL check, so always-on does not break the existing "Alone mode with CAPI credentials" row.

AppSec CA still keys off the explicit AppSec scheme, not `effectiveAppsecScheme`. Same in live/stream. Empty AppSec key is allowed here; `appsec.Prepare` later copies `CrowdsecLapiKey` (often empty in alone). Not this ticket.

No identity reconstruction (client address, user, tenant, Host, trust hop). No reclaim / `New` lifetime change. No research write: CrowdSec AppSec protocol does not own this plugin’s ValidateParams skip list. No new usage packet this phase: `core_plugin_appsec.md` / `core_plugin_middleware.md` are enough to call AppSec Open; the validation contract lives on `core_plugin_middleware_config-validation`.

## Decisions

1. **Alone AppSec checks** — after CAPI `GetVariable` on machine id and password, call `validateAppsecURLKeyAndTLS` only. Do not call `validateLapiAndAppsecConnection` / `validateLapiURLAndKeys`. Do not add an enabled-or-fields predicate.
2. **Tests** — add `Test_ValidateParams` table rows in `pkg/configuration/zzz_configuration_test.go` (invalid AppSec CA; missing AppSec key file; existing alone+CAPI still ok). Do not require the hunt function name.
3. **Spec** — fold alone AppSec scenarios onto `core_plugin_middleware_config-validation`. Keep MAY-skip as LAPI-only.
4. **Bound** — no live/stream validator rewrite, no AppSec client-cert parse at ValidateParams, no Prepare / Open / reclaim / failure-action change.

## Open questions

- Q: After CAPI checks in alone, always run `validateAppsecURLKeyAndTLS`, or only when AppSec is enabled or TLS/key fields are set?
  Decision: resolved — always call `validateAppsecURLKeyAndTLS`. Spec AppSec URL/CA are not mode-scoped; live/stream already always-on; the hunt cases are covered; a gate would leave alone+disabled+bad-host passing while siblings fail. Smallest delta is the existing helper, not a third shape.
  By: explore

- Q: Must the regression be named `TestHunt_ValidateParams_aloneModeStillRejectsInvalidAppsecCA`?
  Decision: resolved — yes; keep the `Test_ValidateParams` table rows and add that hunt function name as a dedicated test. Conductor bound the named hunt proof.
  By: implement

- Q: Should alone AppSec CA parse use `effectiveAppsecScheme` (inherit LAPI `https`) instead of explicit `CrowdsecAppsecScheme == https`?
  Decision: assumed — keep today’s explicit-scheme trigger. Changing it would rewrite live/stream validation (out of scope). Hunt proof uses an explicit AppSec `https` scheme.
  By: explore

- Q: Who owns AppSec key/TLS facts at startup — ValidateParams or `appsec.Prepare`?
  Decision: resolved — `validateAppsecURLKeyAndTLS` owns URL, key-file existence, and HTTPS CA PEM. `appsec.Prepare` owns secret copy and scheme fallback after validation. Reuse the validator; do not re-derive those checks in Prepare or New.
  By: explore
