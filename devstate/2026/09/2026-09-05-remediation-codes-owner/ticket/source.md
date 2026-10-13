# Remediation codes owner

Fact ownership: cache owns CrowdSec vocabulary. Desired: decisionscope owns ban/captcha/none codes; captcha owns grace-done code; cache remains a dumb store. Wire values on disk unchanged (`t`/`c`/`f`/`d`) so Redis/memory entries stay compatible.

Remediation codes `t` / `c` / `f` live in `pkg/cache` (`BannedValue`, `CaptchaValue`, `NoBannedValue`). Four packages import a KV store just to name a ban. Those constants belong on `pkg/decisionscope`. Captcha grace `d` (`CaptchaDoneValue`) belongs on `pkg/captcha`.

`pkg/cache` stays a string KV (Get/Set/Delete/GetMany, CacheMiss, CacheUnreachable). Update all call sites (bouncer, crowdsecconnection, decisionscope, captcha, tests). Do not invent `pkg/remediation`. Do not change cache Redis/memory behavior. Do not drop configuration import from decisionscope (sibling). Do not split connection.go.

Sibling tickets you MUST NOT take: 2026-09-05-split-connection-files, 2026-09-05-split-configuration-files, 2026-09-05-split-ip-trust, 2026-09-05-scope-headers-identity, 2026-09-05-decisionscope-mode-bool, 2026-09-05-config-prepare-snapshot.
