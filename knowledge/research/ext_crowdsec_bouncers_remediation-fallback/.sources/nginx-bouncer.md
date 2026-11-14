---
url: https://docs.crowdsec.net/u/bouncers/nginx
title: NGINX IP Blocking, CAPTCHA & WAF with CrowdSec
fetched: 2026-11-14
authority: official
---

FALLBACK_REMEDIATION: "> ban | captcha", sample "FALLBACK_REMEDIATION=ban". "The fallback remediation is applied if the component receives a decision with an unknown remediation."

BOUNCING_ON_TYPE: "> all | ban | captcha", sample "BOUNCING_ON_TYPE=all". "Type of remediation we want to bounce." "If you choose `ban` only and receive a decision with `captcha` as remediation, the component will skip the decision."
