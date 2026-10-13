# Code review — Performance
Pin: origin/master...HEAD

## Findings

- [accepted] **One `net.IP.String()` per request on the lookup path.** DestBranch used the raw
  client string as the key with no formatting; the apply formats the parsed address instead.
  Argument: it is a fixed-size format of an already-parsed address, on a request that is about to
  issue a Redis `MGET`. The alternative — calling `IPCacheKey(remoteIP)` — would parse the string
  again on top of that, which is strictly worse. No extra allocation was traded for a second parse.

- [resolved] **The store path gains at most one `net.ParseIP` per decision.** It runs only when
  `net.ParseCIDR` failed, i.e. for bare values, once per decision per stream poll — not per request.

- [resolved] **The live-mode measurement moved the right way.** 5 requests from one address:
  1 LAPI query before and after. 4 spellings of one address: 4 queries before, 1 after. A range apply
  still performs exactly one read and one write.
