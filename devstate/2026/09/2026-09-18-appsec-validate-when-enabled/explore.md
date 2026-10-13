# Explore

## Concepts

`crowdsecMode` picks the decision source. `crowdsecAppsecEnabled` is the only knob that means this router will talk to AppSec. `New` already uses that knob for `appsec.Open` (`plugin.go`). `ValidateParams` does not.

```
ValidateParams today
        │
        ├─ alone ──► CAPI machine + password ──► skip LAPI and AppSec
        │
        └─ live / stream / none / appsec
                    └──► LAPI URL/key/TLS
                    └──► validateAppsecURLKeyAndTLS   ← never reads enabled
```

`getMinimalConfig()` is `New()` plus a LAPI key. AppSec stays off (default false). Default AppSec host is `crowdsec:7422`; default failure action is ban.

`validateAppsecURLKeyAndTLS` checks AppSec URL (effective scheme), `GetVariable("CrowdsecAppsecKey")` (reads `CrowdsecAppsecKeyFile` when set), and AppSec CA PEM when `CrowdsecAppsecScheme == https` and insecure-verify is false. Empty AppSec key is allowed (later `appsec.Prepare` copies the LAPI key).

Measured dest (`go test ./pkg/configuration -run Test_ValidateParams/AppSec_HTTPS_with_invalid_CA_while_LAPI_HTTP`): table case wants an error with AppSec off. Alone + AppSec on + garbage CA is not in the table and would pass today because the alone branch never calls the helper.

Closed PR #80 (`2026-09-18-alone-mode-skips-appsec-validation`) always called `validateAppsecURLKeyAndTLS` from alone, even when AppSec was off. That is the rejected twin of this ticket.

This work does not reconstruct client address, user, tenant, Host, or trust hop. It does not change reclaim, tickers, or `New` lifetime. Redis leftover-password `GetVariable` stays as dest (always runs). No third-party AppSec protocol fact is missing for the gate; usage packet `core_plugin_middleware_config-validation.md` is captcha-only today.

## Decisions

- Gate AppSec URL / key-file / HTTPS CA on `config.CrowdsecAppsecEnabled` in every mode. Reuse that Config field; do not invent a second signal (fields-set, leftover host, `crowdsecMode: appsec`).
- Alone still skips LAPI URL, key, and TLS after CAPI machine id and password. Live, stream, none, and appsec still validate LAPI.
- Call `validateAppsecURLKeyAndTLS` from both branches when enabled. Do not hide the gate inside `validateLapiAndAppsecConnection` (alone never calls that function). If that wrapper becomes a one-liner, inline LAPI then the enabled AppSec call and drop the wrapper.
- Do not reuse PR #80 / `validateAloneCapiAndAppsec` / “always validate AppSec knobs in alone”.
- Flip dest tests that assumed live/stream validate AppSec while off. Spec AppSec URL and HTTPS CA scenarios get an enabled `WHEN`. Empty-host shape (#89) stays out.
- After apply, usage packet `core_plugin_middleware_config-validation.md` should name the enabled gate (devdocs-impact). Do not write that contract as if dest already has it.

## Open questions

- Q: Who already owns whether this router will talk to AppSec?
  Decision: resolved — `CrowdsecAppsecEnabled` on `Config`. `New` already uses it for `appsec.Open`. `ValidateParams` reuses that output. Do not re-derive from leftover fields or from `crowdsecMode`.
  By: explore

- Q: Should AppSec URL, key file, and HTTPS CA be validated when `crowdsecAppsecEnabled` is false (PR #80 always-on in alone)?
  Decision: resolved — no. Validate those only when `config.CrowdsecAppsecEnabled` is true, in every mode including alone. Do not reuse closed PR #80 or branch `2026-09-18-alone-mode-skips-appsec-validation`.
  By: explore

- Q: Where does the enabled call sit so alone still skips LAPI?
  Decision: resolved — `ValidateParams` alone: CAPI then `if enabled { validateAppsecURLKeyAndTLS }`. Other modes: LAPI then the same `if`. Do not add the gate only inside `validateLapiAndAppsecConnection`.
  By: explore

- Q: What happens to dest table case "AppSec HTTPS with invalid CA while LAPI HTTP" (`getMinimalConfig()`, AppSec off, `wantErr: true`)?
  Decision: resolved — that leftover-CA case becomes success (intentional vs dest). Add live/stream + AppSec on + invalid CA / missing key file still fail. Add alone + AppSec on fail and alone + AppSec off leftover success (CAPI ok). Set `CrowdsecAppsecEnabled` on the distinct-scheme URL case so it still proves effective scheme.
  By: explore

- Q: Do none and appsec modes share the same enabled gate even though the required test list names live/stream/alone?
  Decision: assumed — yes, all modes. Do not add empty-host (#89) cases. A leftover-CA success under `crowdsecMode: appsec` with AppSec off is allowed if cheap; the existing warn test stays.
  By: propose

- Q: Should AppSec CA parse use `effectiveAppsecScheme` (inherit LAPI `https`) instead of explicit `CrowdsecAppsecScheme == https`?
  Decision: assumed — keep today’s explicit-scheme trigger. Changing inherit-https CA parse would rewrite live/stream validation and is out of scope.
  By: propose

- Q: When AppSec is enabled and the key is empty, should `ValidateParams` fail?
  Decision: assumed — no. Keep the helper’s empty-key pass; `appsec.Prepare` still copies the LAPI key. This ticket only adds the enabled gate around the existing helper.
  By: propose

- Q: Should leftover `CrowdsecAppsecFailureAction` / body-limit checks also skip when AppSec is off (Redis leftover-password analog)?
  Decision: assumed — leave them. Failure-action behavior is out of scope. Dest still always `GetVariable`s `RedisCachePassword`; do not change Redis in this ticket.
  By: propose

- Q: Does this change `appsec.Prepare`, reclaim, or `New` process lifetime?
  Decision: assumed — no. `ValidateParams` is the constructor gate. Runtime AppSec client, reclaim, and failure-action stay out.
  By: propose

- Q: Should leftover AppSec fields warn when the knob is false?
  Decision: assumed — no. Ticket is skip validation, not a new warn. Bound the ask.
  By: propose
