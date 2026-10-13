# 2026-09-24-bouncer-bind-race

Fix Finding 1 only, from review-findings.md.

Finding 1 — In-place client bind races the request path.
storeBinding in pkg/bouncer/bouncer.go keeps one *reclaim.Box and assigns boxed.Value on later publishes. Unbox in pkg/reclaim/default.go reads boxed.Value on every ServeHTTP. Box.Value is a plain any. The atomic.Value only publishes the *Box pointer. ReceiveLAPI / ReceiveAppSec / ReceiveCaptcha run from reclaim.Watch while ServeHTTP is in flight. That is a data race: torn interface can panic the request (ServeHTTP has no recover), or a request can see a nil/stale client and take the failure action or the wrong LAPI mode. Contract: openspec/specs/core_plugin_middleware_bouncer/spec.md requirement "Bouncer binds clients through atomic late bind" (Load only; nil client must not panic; mode follows the published client).

Yaegi requires the atomic.Value's concrete type to stay *reclaim.Box. The fix shape that satisfies that: dest.Store(&reclaim.Box{Value: value}) on every update so each Load sees an immutable snapshot. Do not mutate Box.Value in place. Do not take Findings 2 or 3. Do not refactor unrelated bouncer policy.
