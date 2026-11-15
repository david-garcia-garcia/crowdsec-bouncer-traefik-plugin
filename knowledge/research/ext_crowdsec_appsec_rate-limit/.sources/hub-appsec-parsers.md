---
url: https://github.com/crowdsecurity/hub/blob/45ddd98db0db97d9da2b21d2bcf007b5cecd3c3f/parsers/s01-parse/crowdsecurity/appsec-rate-limit-logs.yaml
title: Hub AppSec parsers vs rate-limit events
fetched: 2026-11-14
authority: source
ref: github.com/crowdsecurity/hub@45ddd98db0db97d9da2b21d2bcf007b5cecd3c3f:parsers/s01-parse/crowdsecurity/
---

`appsec-logs.yaml` filter: `evt.Parsed.program == 'appsec' && evt.Parsed.source not in ['crowdsec-appsec-challenge', 'crowdsec-appsec-rate-limit']`. Rate-limit events are excluded from the generic AppSec parser, so `appsec-vpatch` (filter `log_type == 'appsec-block'`) never sees them.

`appsec-rate-limit-logs.yaml` filter: `evt.Parsed.source == 'crowdsec-appsec-rate-limit'`; sets `log_type: appsec-rate-limit`, `rate_limit_key`, `rate_limit`, and the usual request metas.

grep at this commit: no collection references `appsec-rate-limit-logs`; no scenario filters on `appsec-rate-limit`.
