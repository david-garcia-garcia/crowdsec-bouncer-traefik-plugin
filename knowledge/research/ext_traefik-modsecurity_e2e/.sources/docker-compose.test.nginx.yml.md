---
url: https://github.com/david-garcia-garcia/traefik-modsecurity/blob/e860d2494f41d49172f2d8aae916615c8ee356e1/docker-compose.test.nginx.yml
title: docker-compose.test.nginx.yml (nginx-drain)
fetched: 2026-10-12
authority: source
ref: github.com/david-garcia-garcia/traefik-modsecurity@e860d2494f41d49172f2d8aae916615c8ee356e1:docker-compose.test.nginx.yml
---

Same Traefik and whoami route labels as docker-compose.test.yml. waf image owasp/modsecurity-crs:4.3.0-nginx-alpine-202406090906. MODSEC_AUDIT_LOG=/tmp/modsecurity/modsec_audit.log. REAL_IP_HEADER=X-Real-IP, SET_REAL_IP_FROM=10.0.0.0/8,172.16.0.0/12,192.168.0.0/16 (comma-separated), REAL_IP_RECURSIVE=on. Volumes: crs-nginx/realip.conf, drain-origin.conf, proxy_backend.drain.conf.template. HEALTHCHECK wget 127.0.0.1:8080. Same whoami / waf-5xx / echo-ws services as apache-drain.
