# Standards

1. [judgement] Mysterious Name — `pkg/lapi/client_http.go:142` — `replaced` is `fieldsDiffer` (timeout/TLS extras changed), not “Swap happened”
   → Rename the bool (and the OpenStream/OpenLive locals) to the role: `timeoutOrTLSChanged`
   Status: skipped
   Argument: judgement; documented return is fieldsDiffer, not a commandment placeholder.
