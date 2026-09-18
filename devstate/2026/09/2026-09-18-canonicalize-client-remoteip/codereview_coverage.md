# Test coverage

1. [hard] Ticket job unproven — `pkg/bouncer/bouncer.go:179` — after a successful parse, `req.remoteIP = req.ipAddr.String()`; no test fails if that line is reverted. `TestClientRequestRemoteIPIsCanonical` only hits `testClientRequest`. `lookupAsRequest` / `liveRequests` canonicalize in the helper before `LookupCachedRemediation` / `LiveLookup`. e2e requests already-canonical XFF (`2001:db8::b1:1`, `203.0.113.81`) so DestBranch `IPLookupCacheKey` would still ban
   → Drive ServeHTTP (or the real-stack XFF case) with a non-canonical request spelling against a store keyed under `net.IP.String()`, and assert ban
   Status: done
   Argument: TestServeHTTP_NonCanonicalHeaderHitsCanonicalIpBan drives ServeHTTP with expanded XFF against a canonical Ip slot.
