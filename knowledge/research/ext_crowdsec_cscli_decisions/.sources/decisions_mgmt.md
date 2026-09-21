---
url: https://docs.crowdsec.net/u/user_guides/decisions_mgmt/
title: Decisions (user guide)
fetched: 2026-09-05
authority: official
---

Add: sudo cscli decisions add -i 192.168.1.1 (default duration 4h, type ban).
Add with --duration 24h --reason; add --type captcha.
Delete: sudo cscli decisions delete --ip 192.168.1.1
cscli decisions list shows only the latest alert per IP; several decisions can exist. To clear all for an IP use cscli decisions delete -i x.x.x.x
SOURCE cscli means a manual decision from cscli.
delete --all flushes all bans including local and community.
