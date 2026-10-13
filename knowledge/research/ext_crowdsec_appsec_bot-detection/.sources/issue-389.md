---
url: https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/389
title: Issue 389 AppSec bot-detection not supported yet
fetched: 2026-09-05
authority: ticket
---

Reporter: CrowdSec 1.8.0 + plugin v1.7.1 + crowdsecurity/appsec-bot-* in acquis → every Traefik-routed request 403; cscli metrics Blocked 0; challenges Requested but never Submitted/Solved; engine log unable to write response: broken pipe on AppSec listener.

Quotes official enable warning: unsupported bouncers most likely silently refuse every client. Cites https://docs.crowdsec.net/docs/v1.8/appsec/bot_detection/enable

Maintainer mathieuHa (collaborator): not a bug; not supported by the plugin yet; PR 343 ongoing. CrowdSec released it days earlier.
