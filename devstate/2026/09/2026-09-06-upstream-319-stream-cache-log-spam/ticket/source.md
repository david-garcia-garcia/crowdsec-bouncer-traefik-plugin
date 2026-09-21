# Upstream issue #319

Title: [BUG] Traefik logs filling up with "msg=handleStreamCache:updated" after upgrade to v1.6.0-alpha

URL: https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/319

State: CLOSED

Labels: bug

Created: 2026-03-15T06:42:45Z

## Body

After upgrading to v1.6.0-alpha, Traefik logs are full of the same message repeating every minute:

`level=INFO msg=handleStreamCache:updated component=CrowdsecBouncerTraefikPlugin`

Expected: message should only appear once and not appear every minute.

Version: Unraid 7.2.4, Traefik 3.6.10, Plugin 1.6.0-alpha, Redis 8.6.1.

Repro: upgrade to v1.6.0-alpha, check Traefik logs, see repeating message.
