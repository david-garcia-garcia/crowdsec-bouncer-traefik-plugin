---
url: https://docs.crowdsec.net/docs/next/contributing/specs/bouncer_appsec_specs.md
title: Specifications for Remediation Component and AppSec Capabilities
fetched: 2026-09-18
authority: official
---

Stream mode is default. GET /decisions/stream, startup=true then deltas. Recommended pull 10s (stream_update_frequency).
Store decisions in memory. There can be multiple decisions per IP; store each independently (own remediation and TTL). Ranges are stored too; do not explode a range into IPs.
Pruning: when you GET you will receive "deleted" decisions; also clean after a GET or periodically for expired TTL.
This page does not say to apply deleted before new, or new before deleted.
Appendix Decision example JSON lists "deleted" then "new" (field order in the example, not an apply rule).
Nginx + lua-cs-bouncer named as the complete reference implementation.
