Validate AppSec URL, key file, and HTTPS CA only when crowdsecAppsecEnabled is true, in every mode. If AppSec is off, leftover AppSec settings must not fail ValidateParams — unused knobs must not block boot (same rule as Redis-off leftover password file).

Current master (`pkg/configuration/configuration.go`):
- live/stream call validateLapiAndAppsecConnection, which always calls validateAppsecURLKeyAndTLS with no enabled gate. Leftover missing crowdsecAppsecKeyFile or explicit-https garbage CA can fail a router that has AppSec off.
- alone skips the whole LAPI+AppSec validator after CAPI credentials, so even AppSec-on + garbage CA / missing key file pass. Default AppSec failure action is ban, so those requests drop at runtime.
- validateAppsecURLKeyAndTLS itself never checks CrowdsecAppsecEnabled.

Desired:
- In all modes: if config.CrowdsecAppsecEnabled { validateAppsecURLKeyAndTLS }.
- Alone still skips LAPI URL/key/TLS; still requires CAPI machine id and password.
- Live/stream still validate LAPI; AppSec checks only when enabled.
- Do not validate AppSec host/URL/key/CA when the enabled knob is false, even if leftover fields are set.

Tests must cover:
- alone + AppSec enabled + invalid CA or missing key file → ValidateParams fails.
- alone + AppSec disabled + leftover invalid CA / missing key file → ValidateParams succeeds (CAPI ok).
- live or stream + AppSec disabled + leftover invalid AppSec CA / missing key file → ValidateParams succeeds (LAPI ok). This is an intentional behavior change vs master.
- live or stream + AppSec enabled + invalid AppSec CA / missing key file → still fails.

Update any existing tests or specs that assumed live/stream always validate AppSec when the feature is off. Bound the ask to this validation gate only. Do not take empty-host (#89) or other AppSec URL shape work unless this change requires a test update.
