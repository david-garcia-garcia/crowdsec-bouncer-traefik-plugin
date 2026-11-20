---
url: https://github.com/david-garcia-garcia/traefik-modsecurity/blob/e860d2494f41d49172f2d8aae916615c8ee356e1/docker-compose.test.yml
title: docker-compose.test.yml (apache-drain)
fetched: 2026-10-12
authority: source
ref: github.com/david-garcia-garcia/traefik-modsecurity@e860d2494f41d49172f2d8aae916615c8ee356e1:docker-compose.test.yml
---

traefik: traefik:v3.7.12, ports 8080:8080 and 8000:80, accesslog JSON with X-Waf-Status=keep, localPlugins moduleName github.com/david-garcia-garcia/traefik-modsecurity, bind `.` → plugins-local src, `./test-dynamic` file provider, sanitizePath=false.

waf: owasp/modsecurity-crs:4.3.0-apache-alpine-202406090906. REMOTEIP_HEADER=X-Real-IP, REMOTEIP_INT_PROXY=10.0.0.0/8 172.16.0.0/12 192.168.0.0/16. Volume crs-apache/httpd-vhosts.drain.conf. MODSEC_REQ_BODY_LIMIT 10MB.

Services/routes: whoami-reclaim (no labels); whoami-protected `/protected` waf-middleware (url http://waf:8080, timeout 3000, X-Waf-Status, maxBodySizeBytes=1024, logLevel=debug); whoami-bypass `/bypass` no plugin; whoami-remediation-test backoff 5s threshold 1; whoami-error-test invalid-waf-url:9999 backoff 5s threshold 1; whoami-force-test maxBody 1024; whoami-large-body-test maxBody 20971520 timeout 30000; whoami-threshold-test backoff 10s threshold 3 window 30; whoami-pool-test maxBody 5120 pool 1024; waf-5xx nginx + test-fixtures/waf-5xx.conf; whoami-waf-5xx-test url http://waf-5xx:80 (backoff omitted); whoami-chain-retry WAF then retry; whoami-chain-buffer buffering then WAF; echo-ws jmalloc/echo-server:v0.3.7 `/ws-echo` behind waf-middleware.
