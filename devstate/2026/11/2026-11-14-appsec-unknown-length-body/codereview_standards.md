# Standards

1. [hard] Leave a trail — `pkg/configuration/zzz_appsec_body_test.go:10` — new test functions `TestNew_AppsecBodyDefaults` (:10), `TestEffectiveAppsecBodyLimit` (:20), `TestValidateParams_AppsecBodyKnobs` (:37), and `pkg/appsec/zzz_session_test.go` `TestKey_BodyReadTimeoutChangesIdentity` (:129) and `TestPrepare_NonPositiveBodyLimitSharesDefaultIdentity` (:138) have no job comment; `TestValidateParams_AppsecBodyKnobs` runs four cases (defaults, zero timeout, negative limit, zero limit) with no block intros, while every other new test in this diff has one
   Fix: Add a one-line job comment to each of the five tests (e.g. "proves appsecBodyLimit 0 / -1 after Prepare share the omitted-limit AppSec Key") and a one-line intro before each case block in `TestValidateParams_AppsecBodyKnobs`
   Status: done
   Argument: Job comments on the five tests and one intro per case block in `TestValidateParams_AppsecBodyKnobs`.
2. [judgement] Leave a trail — `pkg/appsec/query.go:59` — `ErrClientDisconnected` ("while buffering a readable body") and `isClientGoneBodyReadErr` at `:106` ("while buffering a readable client body") still contrast with the unreadable-body class this change removes; every forwardable body is now read, so "readable" names a distinction that no longer exists
   Fix: Drop "readable" from both comments (e.g. "while buffering the client body for AppSec")
   Status: skipped
   Argument: judgement; comment wording only, not applied unattended — devdocs impact rewrites the client-gone wording with the removed unreadable class.
3. [judgement] Data Clumps — `pkg/appsec/query.go:140` — `req` plus `responseController` now travel together as a pair of parameters through `Query` → `newAppsecForwardRequest` (:204) → `newAppsecBodyRequest` → `readClientBodyForAppsec` (:266); only the last callee uses the controller, the three hops above only pass it on (One job, one owner: co-traveling cluster on many callees)
   Fix: Either keep the parameter but stop it at the hop that needs it (build the body request in `Query` and pass the controller only to `readClientBodyForAppsec`), or give the pair one small owner type for the inbound exchange (request + its response controller) passed down instead of two parameters
   Status: skipped
   Argument: judgement; the controller is threaded through the AppSec request build that owns the read (approved deviation row, explore); not applied unattended.
4. [judgement] Smallest durable delta — `tests/e2e/mock/scenarios/appsec/run.sh:12` — `assert_access_log_answered_within` is a generic assertion (reads `$WORKDIR/traefik.log`, writes `failure.txt`) defined inside one scenario, while every other `assert_*` helper (`assert_status`, `assert_header`, `assert_body_contains`) lives in `tests/e2e/mock/lib/common.sh`; scenario files otherwise define only `body`/`cleanup`
   Fix: Move `assert_access_log_answered_within` into `tests/e2e/mock/lib/common.sh` next to `assert_header`
   Status: skipped
   Argument: judgement; the helper has one scenario caller; moving it to `tests/e2e/mock/lib/common.sh` is a shared-lib change, not applied unattended.
