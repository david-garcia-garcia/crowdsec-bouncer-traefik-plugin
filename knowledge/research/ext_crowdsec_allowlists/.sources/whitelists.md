---
url: https://docs.crowdsec.net/u/getting_started/post_installation/whitelists
title: Whitelists (post-installation)
fetched: 2026-11-14
authority: official
---

"There are three whitelist types in CrowdSec:" Parser, Postoverflow, AllowLists.

Parser: "Parser-based whitelists are applied while the event is being enriched." "They prevent the log line from reaching the scenario stage, which saves resources." "Enricher whitelists apply to every event (each log line)."

Postoverflow: "Postoverflow whitelists are applied after a scenario triggers." "Use this stage for _expensive_ checks, such as DNS lookups." "Postoverflow whitelists apply only to triggered scenarios."

AllowLists: "AllowLists let you centrally manage whitelisted IP addresses and CIDR ranges using `cscli`." "This is the preferred method because AllowLists integrate with major components, including:" (list includes AppSec component). "This excludes the IP across all CrowdSec components."

Existing decisions: "Whitelisting an IP address or event will prevent the events from triggering new decisions" "however, any existing decisions will still be applied." "You must manually remove the decisions by running:" (cscli decisions delete).

No "whitelist" or "allow" decision type on the page.

Links: /docs/log_processor/whitelist/intro/, /docs/cscli/cscli_allowlists/.
