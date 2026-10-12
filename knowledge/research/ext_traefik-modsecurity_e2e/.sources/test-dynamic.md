---
url: https://github.com/david-garcia-garcia/traefik-modsecurity/blob/e860d2494f41d49172f2d8aae916615c8ee356e1/test-dynamic/reclaim.yml
title: test-dynamic file-provider fixtures
fetched: 2026-10-12
authority: source
ref: github.com/david-garcia-garcia/traefik-modsecurity@e860d2494f41d49172f2d8aae916615c8ee356e1:test-dynamic/reclaim.yml
---

reclaim.yml: routers reclaim-a and reclaim-b PathPrefix `/reclaim-a` `/reclaim-b`, shared middleware waf-reclaim (modSecurityUrl http://waf:8080, timeoutMillis 3000, logLevel debug), service whoami-reclaim:80. Tests rewrite timeoutMillis to force a new reclaim key.

chain-retry-replay.yml (same directory): router retry-force PathPrefix `/retry-force` priority 100, middlewares waf-chain-retry@docker and retry-chain@docker, loadBalancer first server http://no-such-backend:80 then http://whoami-chain-retry:80.
