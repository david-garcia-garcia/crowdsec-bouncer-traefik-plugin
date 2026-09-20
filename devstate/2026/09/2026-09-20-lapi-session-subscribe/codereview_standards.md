# Standards

1. [hard] Name for the scope — `pkg/lapi/liveholders.go:15` — reclaim `holder` nickname (and listed placeholder `h`) for a Traefik-name registry; Open already passes `middlewareName`; sibling is `registerLiveHeaderScopes`
   → Rename to the Traefik-name job (`liveMiddlewareNames`, `registerLiveMiddlewareName`, param `middlewareName`, slog `middlewareNames`); receiver not `h`
   Status: done
   Argument: renamed liveHolders → liveMiddlewareNames; file livemiddlewarenames.go
2. [hard] Name for the scope — `pkg/lapi/session.go:163` — `finishBind` is a vague verb; param `created` is openClient’s producer flag while this body only skips WARN on first create
   → Name the function for adopt + register + warn; name the bool for the role here (`reused` / join-or-Wake), not `created`
   Status: done
   Argument: finishBind → adoptRegisterAndWarn(reused)
3. [hard] Name for the scope — `pkg/lapi/sessionresidue.go:81` — `a` and `b` are placeholders
   → Name the two slices by role (`residue`, `joiner` or `left`, `right`)
   Status: done
   Argument: stringSlicesEqual(residue, joiner)
4. [hard] Name for the scope — `pkg/lapi/zzz_session_test.go:344` — `createStore` is the producer’s create() suffix; this body only compares the DecisionStore pointer
   → Rename to the role (`firstDecisionStore`)
   Status: done
   Argument: createStore → firstDecisionStore
5. [hard] Name for the scope — `pkg/lapi/zzz_session_test.go:92` — new test locals `a` and `b` are placeholders
   → Name the two configs by role (`firstKey`, `otherKey`)
   Status: done
   Argument: TestSessionKey_DifferentLapiKeysAreDistinct locals firstKey/otherKey
6. [hard] Leave a trail — `pkg/decisionstore/store.go:55` — edited Store comment still calls it a reclaim `incarnation` after this change made Store a Client child
   → Comment the job (intern + Range + engine for one Client), not reclaim incarnation
   Status: done
   Argument: Store comment names Client child job
7. [judgement] Duplicated Code — `pkg/lapi/session.go:111` — OpenStream and OpenLive copy the same `replaced` adopted-INFO block
   → Move that log into `finishBind` (or one shared helper) so the line has one owner
   Status: skipped
   Argument: judgement; OpenStream still registers header scopes after adopt, so the INFO block is not identical.
