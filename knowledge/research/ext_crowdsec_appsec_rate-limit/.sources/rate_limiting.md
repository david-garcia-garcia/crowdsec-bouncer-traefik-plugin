---
url: https://docs.crowdsec.net/docs/appsec/rate_limiting
title: CrowdSec WAF Rate Limiting
fetched: 2026-11-14
authority: official
ref: github.com/crowdsecurity/crowdsec-docs@84602c95254a6734a3bad8b0939981fd34e84320:crowdsec-docs/docs/appsec/rate_limiting.md (identical to versioned_docs/version-v1.8/appsec/rate_limiting.md)
---

`RateLimit()` is available in `pre_eval` hooks. Type `func(key str, limit str, source str?) bool`.

Quick example:

```yaml
name: custom/my-appsec-config
inband:
  pre_eval:
    - filter: req.URL.Path == "/login" && req.Method == "POST"
      apply:
        - RateLimit("login", "5/m")
```

- key: string literal; unique across the whole AppSec configuration (top-level, `inband`, `outofband`). "Each key has its own, independent budget per client."
- limit: `<count>/<s|m|h>`, string literal, positive integer, single unit (`"1/5m"`, `"10/d"` invalid). Invalid limit, non-literal argument or duplicate key prevents the AppSec datasource from starting.
- source (optional): default per client IP; IPv4 per address, IPv6 per /64. Third argument counts on another value; empty value falls back to the IP; a value never consumes an IP budget.
- Return: `true` when over the limit (and blocked). The helper blocks by itself.
- Token bucket: starts with `count` tokens, refills `count` per period. `"3/m"`: 3 at once, the 4th is blocked, one token back every 20 s.
- Over limit: WAF rules not evaluated; "The remediation component is instructed to apply a `ban` remediation."; "The HTTP code returned to the user is always `429 Too Many Requests` (it does not follow `user_blocked_http_code`). The HTTP code returned to the remediation component follows `blocked_http_code` as for any other blocked request."
- Limiters shared by all routines of one AppSec datasource; memory only; "reset when CrowdSec restarts or reloads".
- In-band only. Out-of-band calls do nothing (warning once per key). Only `pre_eval`; `on_load`, `post_eval`, `on_match`, challenge hooks fail at load.
- Events: every blocked request -> event with `evt.Parsed.source = crowdsec-appsec-rate-limit`, parsed by `crowdsecurity/appsec-rate-limit-logs` (must be installed).
- Alerts: "the first time a client goes over the limit of a key, CrowdSec sends an alert with the `rate limit exceeded` scenario"; no further alert until the client was idle a full period.
- "While we do not provide scenarios for this out of the box, you can use these events to write your own scenarios, for example to ban clients that keep going over a limit" (example scenario carries `labels: remediation: true`).
- Metrics: `cs_appsec_rate_limited_total{source,appsec_engine,key}`, `cs_appsec_rate_limiters{appsec_engine,key}`.
