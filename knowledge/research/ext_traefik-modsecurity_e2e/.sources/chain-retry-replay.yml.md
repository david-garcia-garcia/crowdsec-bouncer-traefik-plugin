---
url: https://github.com/david-garcia-garcia/traefik-modsecurity/blob/e860d2494f41d49172f2d8aae916615c8ee356e1/test-dynamic/chain-retry-replay.yml
title: test-dynamic/chain-retry-replay.yml
fetched: 2026-10-12
authority: source
ref: github.com/david-garcia-garcia/traefik-modsecurity@e860d2494f41d49172f2d8aae916615c8ee356e1:test-dynamic/chain-retry-replay.yml
---

File-provider router retry-force: PathPrefix `/retry-force`, priority 100, middlewares waf-chain-retry@docker and retry-chain@docker. loadBalancer servers: http://no-such-backend:80 then http://whoami-chain-retry:80. Comment: first LB server is a missing Docker DNS name (fast fail); path is distinct so PathPrefix(`/chain-retry`) cannot shadow it.
