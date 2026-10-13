---
url: https://docs.crowdsec.net/docs/v1.7/cscli/cscli_decisions_add
title: cscli decisions add (CrowdSec v1.7)
fetched: 2026-09-05
authority: official
---

Add decision to LAPI.
Examples: cscli decisions add --ip 1.2.3.4; --range; --ip with --duration 24h --type captcha.
-i / --ip: Source ip (shorthand for --scope ip --value <IP>)
-d / --duration: default "4h"
-t / --type: default "ban" (ban, captcha, throttle)
