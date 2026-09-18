# Explore

## Concepts

`ValidateParams` runs in `plugin.New` before `appsec.Open`. Non-alone modes always call `validateAppsecURLKeyAndTLS`, including when AppSec is off. That helper only asks `validateURL` whether `http.NewRequest` accepts `scheme://host/path`. Empty `CrowdsecAppsecHost` becomes `http:///` and returns nil. `CrowdsecAppsecHost` is not in `validateParamsRequired`. `New()` still defaults the host to `crowdsec:7422` and `CrowdsecAppsecFailureAction` to `ban`.

When AppSec is enabled, `appsec.Open` stores that host on the AppSec Client. `Query` rebuilds the listener URL from the same field. `Do` on the empty-host URL is unreachable; default failure action is an error; `applyAppsecServeHTTP` bans (`ReasonAPPSEC`).

This ticket does not reconstruct request identity. Listener host stays `Config.CrowdsecAppsecHost` (`appsec.identity`, `Query`). Client address stays `pkg/ip.GetRemoteIP`. Request Host stays the inbound header / `X-Crowdsec-Appsec-Host`.

```
operator YAML
    │
    ▼
ValidateParams ──► validateAppsecURLKeyAndTLS ──► validateURL
    │                    (non-alone always)         NewRequest(http:///)
    │                                               empty host → nil
    ▼
plugin.New / appsec.Open
    ▼
Query listener URL from CrowdsecAppsecHost
    ▼
Do unreachable → failure action ban (default)
```

Measured (temp `TestRepro_ValidateParams_acceptsEmptyAppsecHost*`, deleted): `ValidateParams` returns nil for empty `CrowdsecAppsecHost` when enabled and when disabled. Measured (`http.NewRequest`): empty host `http:///` accepted; whitespace-only `http://%20%20%20/` already rejected; spaced host already rejected (`Test_validateURL`).

No OpenSpec change on this branch (`openspec list --json` empty). Existing spec `core_plugin_middleware_config-validation` covers effective AppSec scheme and “invalid host fails” under that scheme, not “enabled + missing host”.

Consumed: `knowledge/devdocs/index.md` (no `always`), `index_core_plugin.md` → `core_plugin_middleware.md`, `core_plugin_appsec.md`; `knowledge/research/index.md` (no `always`), `index_ext_crowdsec.md` → `ext_crowdsec_appsec_protocol/`, `ext_crowdsec_bouncers_failure-action/`. Usage is enough to call AppSec Client / `New`. No Language gap. Official AppSec listen default and this plugin’s ban-on-unreachable default are already in research. No new packet or finding this phase.

## Decisions

1. **Fix site** — reject missing AppSec host in `validateAppsecURLKeyAndTLS` when `CrowdsecAppsecEnabled`, not inside shared `validateURL`. A general host-required change in `validateURL` would also reject disabled-AppSec empty host (out of scope) and is extra versus already-required `CrowdsecLapiHost`.
2. **What “missing” means** — empty `CrowdsecAppsecHost` and any AppSec URL `http.NewRequest` accepts only because `Host` is missing (the `http:///` case). Do not change LAPI `validateURL` callers.
3. **Whitespace-only host** — already rejected by `validateURL` (`NewRequest` parse). No extra TrimSpace rule.
4. **Alone mode** — do not add AppSec URL checks there. `ValidateParams` skips `validateLapiAndAppsecConnection` in alone; that skip is another ticket (`2026-09-18-alone-mode-skips-appsec-validation`).
5. **Failure action / Query / Bouncer** — do not change defaults or remediations. Startup reject is the fix.
6. **Regression** — in-tree `ValidateParams` case: enabled + empty host errors; disabled + empty host still passes (proves `validateURL` was not tightened). Hunt name `TestHunt_ValidateParams_rejectsEmptyAppsecHostWhenEnabled` is not required.
7. **Spec** — propose folds a new SHALL onto existing `core_plugin_middleware_config-validation`. Do not rename `validateURL`.
8. **Devdocs / research** — no write this phase.

## Open questions

- Q: Who already owns AppSec listener Host (and request Host / client address) so this change does not reconstruct it?
  Decision: resolved — listener host is `Config.CrowdsecAppsecHost`; `appsec.identity` and `Query` already use that field. Request Host and `X-Crowdsec-Appsec-Host` stay the inbound request. Client address stays `pkg/ip.GetRemoteIP`. Reuse those owners; do not parse `RemoteAddr` or rebuild listener Host from another signal.
  By: explore

- Q: Should a whitespace-only `crowdsecAppsecHost` be treated as empty?
  Decision: resolved — whitespace-only already fails `validateURL` (`http.NewRequest` parse). This ticket only adds a reject for a missing host that `NewRequest` currently accepts.
  By: explore

- Q: Must the regression use the hunt name `TestHunt_ValidateParams_rejectsEmptyAppsecHostWhenEnabled`?
  Decision: assumed — no; add a normal in-tree `ValidateParams` case. The hunt proof is not in this tree.
  By: explore

- Q: Should `validateURL` require a host for every caller?
  Decision: resolved — no. Gate the missing-host reject on AppSec enabled inside `validateAppsecURLKeyAndTLS` so disabled-AppSec empty host and LAPI `validateURL` stay as they are.
  By: explore

- Q: Should alone + AppSec enabled also reject an empty host in this change?
  Decision: resolved — no. Out of scope; sister ticket owns alone skipping AppSec URL validation.
  By: explore
