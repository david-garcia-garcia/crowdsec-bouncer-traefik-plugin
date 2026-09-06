---
url: https://docs.crowdsec.net/docs/next/contributing/specs/bouncer_appsec_specs
title: Specifications for Remediation Component and AppSec Capabilities
fetched: 2026-09-05
authority: official
---

Push to /usage-metrics. Default interval 30 minutes, min 10 minutes, 0 disables.
Sample still uses item name "blocked", label remediation_type, top-level "features": [], and meta beside metrics rather than inside a metrics window.
Names lua-cs-bouncer (https://github.com/crowdsecurity/lua-cs-bouncer/) and cs-nginx-bouncer as the complete metrics example.
Decision example includes scenario as a decision field (crowdsecurity/ssh-bf), not as a usage-metrics label.
Conflicts with bouncer_metrics_specs and with LAPI swagger/source on this pin. Follow source for accept/store.
