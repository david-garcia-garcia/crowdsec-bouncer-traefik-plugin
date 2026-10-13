---
url: https://docs.crowdsec.net/docs/next/contributing/specs/bouncer_metrics_specs
title: Remediation Component Metrics
fetched: 2026-09-05
authority: official
---

Bouncers should send dropped (byte/packet/request, split by origin/remediation), processed (same units, include bypass), active_decisions (unit ip).
Supported item labels: origin, remediation, ip_type. origin and ip_type should always be set; remediation only if the bouncer has multiple remediations.
lists origin should be lists:<reason> (reason = LAPI field).
Example payload uses "metrics": { "meta": {...}, "items": [...] } as a single object, not an array. feature_flags: []. Item names dropped/processed/active_decisions. Labels in the example: origin+remediation on dropped; none on processed; ip_type on active_decisions.
Existing implementations named: LUA library (NGINX), PHP library (WordPress), Firewall Bouncer (Go).
