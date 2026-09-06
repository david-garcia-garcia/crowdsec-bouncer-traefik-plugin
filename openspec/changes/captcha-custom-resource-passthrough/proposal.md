## Why

Custom captcha widgets (wicketkeeper and similar) load JS and a challenge from paths on the same bouncer-protected host. On `master`, a captcha-flagged IP that requests those paths gets captcha HTML again, so the widget never loads.

## What Changes

- Add public `CaptchaCustomChallengeURL` (`json:"captchaCustomChallengeUrl,omitempty"`) for the custom challenge endpoint (e.g. `/v0/challenge`). Optional: empty means no challenge pass-through. Existing custom four-field validation stays.
- When remediation kind is captcha and `captchaProvider` is `custom`, requests whose path equals the path of `CaptchaCustomJsURL` or `CaptchaCustomChallengeURL` go to the existing pass path (`handleNextServeHTTP`). Ban kind MUST NOT pass through those URLs.
- Match is exact path of the parsed config URL vs `req.URL.Path` (ignore host, query, fragment). Absolute example URLs still match the browser path.
- Matching custom-resource requests pass through for every method, including HEAD. Other captcha HEAD still falls through to ban.
- Captcha template execute map gains `ChallengeURL`. Wire `examples/custom-captcha`. Default `captcha.html` unchanged.
- **Not BREAKING.** New optional key. Default empty.

## Capabilities

### New Capabilities

- `core_plugin_captcha_custom-resource-passthrough`: Custom captcha JS/challenge URL pass-through on captcha remediation; ban stays blocked.

### Modified Capabilities

None.

## Impact

- `pkg/configuration` — new field, default empty, README
- `pkg/captcha` — store challenge URL; path match; template `ChallengeURL`
- `pkg/bouncer` — captcha branch asks captcha Client before HTML/ban; reuse `handleNextServeHTTP`
- `pkg/bouncer/bouncer_test.go`, `pkg/configuration/configuration_test.go`, `pkg/captcha` tests
- `examples/custom-captcha/` README, compose label, `captcha.html`
