---
url: https://github.com/david-garcia-garcia/traefik-modsecurity/blob/e860d2494f41d49172f2d8aae916615c8ee356e1/test-fixtures/waf-5xx.conf
title: test-fixtures/waf-5xx.conf
fetched: 2026-10-12
authority: source
ref: github.com/david-garcia-garcia/traefik-modsecurity@e860d2494f41d49172f2d8aae916615c8ee356e1:test-fixtures/waf-5xx.conf
---

nginx listen 80; location / returns 503 body `sidecar-5xx-marker\n`. Distinctive so Pester can prove the plugin does not copy sidecar 5xx.
