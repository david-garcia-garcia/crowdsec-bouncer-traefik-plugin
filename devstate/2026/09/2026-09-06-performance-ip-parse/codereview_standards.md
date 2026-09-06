# Standards

1. [hard] Name for the scope — `pkg/bouncer/clientrequest.go:14` — field `parsed` names GetRemoteIP’s transform; handlers use it as the client `net.IP` for `ContainsIP` and Range membership without parsing
   → Rename to `clientIP` or `ipAddr` (pair with `remoteIP` string)
   Status: done
   Argument: renamed field to ipAddr (pairs with remoteIP).

2. [hard] Name for the scope — `pkg/bouncer/bouncer.go:126` — local `parsed` from `GetRemoteIP` keeps the producer suffix; ServeHTTP only nil-checks and folds it into handlers
   → Rename to `clientIP` (or reuse the struct field name after literal)
   Status: done
   Argument: unpack is ipAddr; clientRequest field is ipAddr.

3. [hard] Name for the scope — `pkg/decisionscope/lookup.go:67` — parameter `parsed net.IP` names how GetRemoteIP got the value; body only forwards it to `membership.Remediation`
   → Rename to `clientIP` or `ipAddr`
   Status: done
   Argument: parameter is ipAddr; remoteIP stays the cache-key string.

4. [hard] Name for the scope — `pkg/decisionscope/rangemembership.go:41` — parameter `parsed net.IP` names a transform this method no longer performs; body only classifies with `IsContained`
   → Rename to `clientIP` or `ipAddr`
   Status: done
   Argument: parameter is ipAddr, matching IsContained.

5. [hard] Name for the scope — `pkg/ip/network.go:33` — parameter `parsed net.IP` names producer state; `FamilyOfIP` only reads `To4()` on the address
   → Rename to `ipAddr` or `addr`
   Status: done
   Argument: parameter is ipAddr.
