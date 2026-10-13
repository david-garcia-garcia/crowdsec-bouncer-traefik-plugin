---
url: https://github.com/crowdsecurity/crowdsec/blob/909b5157986a2b2c2163300fdaef5ed01289f7d2/pkg/apiserver/middlewares/v1/api_key.go
title: User-Agent stamps bouncer type and version
fetched: 2026-09-05
authority: source
ref: github.com/crowdsecurity/crowdsec@909b5157986a2b2c2163300fdaef5ed01289f7d2:pkg/apiserver/middlewares/v1/api_key.go
---

User-Agent split on "/": [0]=type, [1]=version. If either differs from the row, UpdateBouncerTypeAndVersion. Payload JSON type/name are not this path.
