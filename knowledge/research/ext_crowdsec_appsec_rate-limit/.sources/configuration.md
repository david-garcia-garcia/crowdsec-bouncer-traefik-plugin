---
url: https://docs.crowdsec.net/docs/appsec/configuration
title: AppSec Configuration Syntax
fetched: 2026-11-14
authority: official
ref: github.com/crowdsecurity/crowdsec-docs@84602c95254a6734a3bad8b0939981fd34e84320:crowdsec-docs/docs/appsec/configuration.md
---

AppSec config files "are loaded by the AppSec acquisition datasource via `appsec_configs`". "You can create custom configuration files in `/etc/crowdsec/appsec-configs/`." `name` is required.

`blocked_http_code`: "HTTP status code returned to the remediation component when a request is blocked." `user_blocked_http_code`: "HTTP status code returned to the end user when a request is blocked."

Hooks are scoped per phase under `inband` / `outofband`; legacy top-level `pre_eval` also exists.
