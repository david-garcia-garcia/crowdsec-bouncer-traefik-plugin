---
url: https://docs.crowdsec.net/u/bouncers/firewall
title: Linux Firewall IP Blocking with CrowdSec
fetched: 2026-09-05
authority: official
---

Golang firewall RC: iptables, nftables, ipset, pf. Feature matrix: Stream only. No WAF/AppSec. Fetches new and old decisions from a CrowdSec API and adds them to a blocklist used by supported firewalls.

Config reference includes update_frequency, api_url, api_key, deny_action (DROP|REJECT — firewall action on a matched packet, not LAPI fallback), deny_log. No fail_open, lapi_failure_action, or poll-failure behaviour.

deny_action is what the packet filter does to a banned IP, not what happens when LAPI is down.
