---
url: https://docs.crowdsec.net/u/bouncers/firewall
title: Linux Firewall IP Blocking with CrowdSec
fetched: 2026-09-18
authority: official
---

Golang firewall RC: iptables, nftables, ipset, pf. Stream only.
Fetches new and old decisions from a CrowdSec API and adds them to a blocklist.
update_frequency: frequency to contact the API for new/deleted decisions.
No apply-order rule for deleted vs new on one payload.
