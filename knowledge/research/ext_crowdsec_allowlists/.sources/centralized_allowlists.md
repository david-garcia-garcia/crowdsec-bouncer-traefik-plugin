---
url: https://docs.crowdsec.net/docs/next/local_api/centralized_allowlists
title: AllowLists
fetched: 2026-11-14
authority: official
---

"The AllowLists feature in CrowdSec lets you manage IP-based allowlists at the LAPI level." "AllowLists are limited to IP/range-based rules." "If you need rules based on log elements (such as URLs), Parser Whitelists or Profile Rules might be more relevant."

Table (Area | Action | Real Time):
- Local alerts | Alert is dropped, action logged. | yes
- Blocklists | IP is removed before database insertion | yes
- WAF (AppSec) | Request bypasses AppSec entirely, action logged. | Refreshed every minute
- Bot Detection (AppSec) | Request bypasses Bot detection entirely. | Refreshed every minute
- cscli | Decision is blocked unless special flag is provided | yes

"allowlisted clients are never served the proof-of-work challenge and never issued a challenge cookie."

Commands: cscli allowlists create <name> -d <desc>; add <name> value...; remove; inspect; delete. "This command must be run on the LAPI." Entries: "By default, allowlist entries have no expiration, but you can specify one with the `-e` flag".

Page does not say what happens to decisions that already exist when an entry is added. Page does not mention bouncers / remediation components.
