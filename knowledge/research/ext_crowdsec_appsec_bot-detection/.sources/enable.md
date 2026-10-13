---
url: https://docs.crowdsec.net/docs/next/appsec/bot_detection/enable.md
title: Enable bot detection
fetched: 2026-09-05
authority: official
---

Warning: check the bouncer supports bot detection first. Enabling it behind an unsupported bouncer leads to unexpected behavior, most likely silently refusing every client.

Install: `cscli collections install crowdsecurity/appsec-bot-challenge`

Acquis (typically /etc/crowdsec/acquis.d/appsec.yaml):

```
listen_addr: 127.0.0.1:7422
appsec_configs:
  - crowdsecurity/appsec-default
  - crowdsecurity/appsec-bot-*
labels:
  type: appsec
```

Wildcard matches installed appsec-configs only. Broader crowdsecurity/* also works.

Install one bundle, not several. appsec-bot-challenge, -strict, -permissive each ship a different threshold; wildcard loads every installed one and the strictest wins.

| Collection | Threshold config | Rejects at |
|---|---|---|
| crowdsecurity/appsec-bot-challenge | crowdsecurity/appsec-bot-challenge-scoring-balanced | >= 75 |
| crowdsecurity/appsec-bot-challenge-strict | crowdsecurity/appsec-bot-challenge-scoring-strict | >= 45 |
| crowdsecurity/appsec-bot-challenge-permissive | crowdsecurity/appsec-bot-challenge-scoring-permissive | >= 100 |

Verification: curl a protected route → 200 HTML challenge; Set-Cookie __crowdsec_challenge once solved. Bouncer must forward /crowdsec-internal/challenge/* unchanged.

Metrics funnel: requested → submitted → accepted (solved or granted) or rejected (protocol, submission, or cookie). Exempt column = requests an exclusion config skipped.
