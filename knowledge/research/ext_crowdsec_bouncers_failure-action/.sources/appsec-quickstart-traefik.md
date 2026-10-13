---
url: https://docs.crowdsec.net/docs/next/appsec/quickstart/traefik.md
title: Traefik AppSec quickstart
fetched: 2026-09-05
authority: official
---

CrowdSec docs for the community Traefik plugin (maxlerebourg/crowdsec-bouncer-traefik-plugin). Examples set:

crowdsecAppsecFailureBlock: true
crowdsecAppsecUnreachableBlock: true

Directives:

crowdsecAppsecFailureBlock (bool): If the AppSec Component returns 500 status code should the request be blocked.

crowdsecAppsecUnreachableBlock (bool): If the AppSec Component is unreachable should the request be blocked.

Two separate bools. No lapi_failure_action. No single fail-mode enum. Examples are fail-closed (true/true).
