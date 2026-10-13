## Context

See proposal.md — Why. `CrowdsecAppsecEnabled` already decides `appsec.Open` in `New`. `ValidateParams` does not read that field before AppSec URL/key/CA checks. Alone returns after CAPI and never calls `validateLapiAndAppsecConnection`. Live/stream/none/appsec always call that wrapper, which always calls `validateAppsecURLKeyAndTLS`. Dest table case "AppSec HTTPS with invalid CA while LAPI HTTP" uses `getMinimalConfig()` (AppSec off) and wants an error. Closed PR #80 always validated AppSec knobs from alone even when the knob was off.

## Goals / Non-Goals

**Goals:**
- Gate the existing AppSec URL / key-file / HTTPS CA helper on `config.CrowdsecAppsecEnabled` in every mode.
- Keep the helper body (effective-scheme URL, empty-key pass, explicit-`https` CA parse).
- Flip dest leftover-CA live/stream tests; add alone on/off and live/stream on cases.

**Non-Goals:**
- Empty-host (#89) or other AppSec URL shape work.
- LAPI checks in alone.
- Runtime AppSec client, reclaim, failure-action, body-limit, leftover-field warn.
- Redis leftover-password `GetVariable` (dest always runs it).
- Inherit-https CA parse (`effectiveAppsecScheme` instead of explicit `CrowdsecAppsecScheme == https`).
- Reusing PR #80 / `validateAloneCapiAndAppsec` / always-on AppSec knobs in alone.

## Decisions

1. Owner of “will this router talk to AppSec?” is `config.CrowdsecAppsecEnabled`. Reuse that field. Alternative: leftover fields or `crowdsecMode: appsec` — rejected; `New` already uses the knob (`explore.md` identity-owner).
2. `ValidateParams` alone: CAPI then `if enabled { validateAppsecURLKeyAndTLS }`. Other modes: LAPI then the same `if`. Do not hide the gate only inside `validateLapiAndAppsecConnection` (alone never calls it). If that wrapper becomes a one-liner, inline LAPI then the enabled AppSec call and drop it. Alternative: always-on AppSec from alone (PR #80) — rejected.
3. Keep the helper’s empty-key pass and explicit-scheme CA trigger. Alternative: fail empty key when enabled, or parse CA on inherit-https — rejected; out of scope.
4. Tests stay in `zzz_configuration_test.go`. Flip "AppSec HTTPS with invalid CA while LAPI HTTP" to `wantErr: false`. Set `CrowdsecAppsecEnabled` on the distinct-scheme URL case. Add alone on fail, alone off leftover success (CAPI ok), live/stream on fail, and live/stream off leftover success. A leftover-CA success under `crowdsecMode: appsec` with AppSec off is allowed if cheap; keep the existing warn test.

## Risks / Trade-offs

- [Live/stream leftover invalid CA or missing key file now boots] → intentional vs dest. Routers with AppSec off no longer fail on stale AppSec knobs.
- [Alone + AppSec on + garbage CA now fails closed] → intended. Default AppSec failure action is ban; a boot that skipped the check dropped those requests at runtime.
- [Distinct-scheme URL case would skip URL validation if left AppSec-off] → set enabled so it still proves effective scheme.

## Migration Plan

Validation-only. Roll back by restoring the ungated live/stream AppSec call and the alone skip of the helper.

## Open Questions

None — ticket decisions stand on `explore.md`.
