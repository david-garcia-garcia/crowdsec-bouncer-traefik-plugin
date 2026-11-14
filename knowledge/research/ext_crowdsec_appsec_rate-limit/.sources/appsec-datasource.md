---
url: https://docs.crowdsec.net/docs/log_processor/data_sources/appsec
title: Application Security Component datasource
fetched: 2026-11-14
authority: official
ref: github.com/crowdsecurity/crowdsec-docs@84602c95254a6734a3bad8b0939981fd34e84320:crowdsec-docs/docs/log_processor/data_sources/appsec.md
---

Example acquisition:

```yaml
source: appsec
listen_addr: 127.0.0.1:7422
path: /
appsec_configs:
  - crowdsecurity/appsec-default
labels:
  type: appsec
```

`appsec_configs`: "The list of appsec-configs to use (as seen in `cscli appsec-configs list`)." Glob entries expand to installed configs; a glob matching nothing is an error. `appsec_config` and `appsec_config_path` are deprecated.
