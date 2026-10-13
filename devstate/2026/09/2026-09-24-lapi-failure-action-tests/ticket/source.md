# Add the missing LAPI failure-action request tests

The bouncer, not the stream client, decides whether a request is blocked when LAPI cannot give a verdict. The knob is `bouncerLapiFailureAction` (`passthrough` | `ban` | `captcha`). Default is `ban`. `passthrough` is fail-open. `ban` is fail-closed.

Add tests that assert that knob on the request path. Two holes:

1. A stream-mode plugin whose `GET /v1/decisions/stream` actually fails must honor the knob on the following request. `passthrough` must call next and must not block. `ban` must not call next and must return the ban status. Flipping the healthy flag in the test does not count.
2. `bouncerLapiFailureAction: captcha` must serve the captcha challenge on a LAPI failure. No request-path test does that today.

Do not change the knobs, their values, or their defaults. `bouncerAppsecFailureAction` already has request-path tests for `passthrough`, `ban`, and `captcha`. Do not add AppSec tests unless grounding these two finds a hole.
