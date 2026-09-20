## Why

CrowdSec CAPI and console-subscribed lists always deliver decision type `ban`. Console and `profiles.yaml` cannot change that type, so a visitor on a shared blocklist gets a hard 403. Upstream https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/369 adds `CaptchaBanOrigins` matching raw `decision.Origin`. This fork already stores `MetricsOrigin` (`lists:<scenario>`), so operators can remap one list without remapping every list.

## What Changes

- Add public Config `CaptchaBanOrigins` (`captchaBanOrigins`), default empty (no-op).
- Copy trimmed entries onto `lapi.Client` at `New` (first-create residue; not on the reclaim Open key).
- One helper maps LAPI type + metrics origin to the stored kind letter: listed `ban` → captcha `c`.
- Use that helper on stream Ip/header, stream Range, and live/none query; live strongest pick uses the remapped kind so a still-ban wins over a remapped captcha.
- Match exact metrics origin; config `lists` also matches any `lists:` prefix.
- Document in README. Mock LAPI carries origin/scenario; e2e scenario covers CAPI, `lists:<name>`, and unlisted bans.
- Do not enum-validate origin tokens. Do not require `captchaProvider` (existing captcha→ban fallback).

## Capabilities

### New Capabilities

- `core_plugin_lapi_captcha-ban-origins`: store captcha instead of ban for configured metrics origins, including per-list `lists:<name>`.

### Modified Capabilities

None.

## Impact

- `pkg/configuration/configuration.go`
- `pkg/lapi/client.go`, `pkg/lapi/client_decisions.go`, `pkg/lapi/client_stream.go`, new `pkg/lapi/captcha_ban_origins.go`
- README, mock LAPI, e2e mock scenario
- Out of scope: AppSec, failure-action captcha, Traefik ticker-stop on reload, reclaim key changes
