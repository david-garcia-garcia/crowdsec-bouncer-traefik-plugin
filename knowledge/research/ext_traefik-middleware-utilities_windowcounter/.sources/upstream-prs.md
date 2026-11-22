---
url: https://github.com/david-garcia-garcia/traefik-middleware-utilities/pulls
title: Open windowcounter and tokenbucket fix PRs
fetched: 2026-11-20
authority: source
ref: github.com/david-garcia-garcia/traefik-middleware-utilities PR search "tokenbucket OR windowcounter bug"
---

Open (not merged, in no tag): #54 fix(tokenbucket): admit Allow from wait microseconds; #60 fix(windowcounter): expire leftover exact-mode keys with no TTL; #62 fix(windowcounter): keep per-node cap when Redis is down; #63 fix(windowcounter): GET flushed previous on buffered Take.

Merged before v1.0.7: #52, #53, #55, #56, #57 (tokenbucket); #58, #59, #61, #64, #75 (windowcounter).

Branch heads (origin): tokenbucket-bug-allow-wait-units 00c60cff35977d827c0bd11607be2d51d93c16ef; windowcounter-bug-stale-previous 717c4d6969614df1f19615d8a2f7d887ebc5a162; windowcounter-bug-expire-not-retried 86ec42f96126cfcaf1b0190eeefff43a90efe9dd; windowcounter-bug-buffered-outage d9b24a08949dfa67257620764d453f7906f8c2aa. None is an ancestor of v1.0.7, v1.0.8, or origin/master.
