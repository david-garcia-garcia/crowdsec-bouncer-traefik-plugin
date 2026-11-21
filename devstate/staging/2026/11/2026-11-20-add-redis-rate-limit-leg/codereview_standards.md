# Standards

1. [hard] Symmetry and consistency — `pkg/bouncer/bouncer.go:143` — `rateLimitFailureAction` goes through `EffectiveFailureAction` (empty → `ban`) although its CreateConfig and README default is `passthrough`; ModSec, the sibling leg with the same `passthrough` default, maps empty to `passthrough` via `EffectiveModsecFailureAction` (`pkg/configuration/configuration.go:231`), so an explicit empty `rateLimitFailureAction` bans
   Fix: Map an empty `rateLimitFailureAction` to `passthrough` through one passthrough-default mapper shared with ModSec
   Status: done
   Argument: `bouncer.New` maps `rateLimitFailureAction` through new `configuration.EffectiveRateLimitFailureAction` (empty → passthrough, the ModSec mapper shape); one mapper shared with ModSec would edit ModSec code outside this diff, so the two stay twins; `TestRateLimit_failureActions` case "empty is passthrough"; design decision 11 updated.
   Quote:
   ```
   rateLimitFailureAction:   configuration.EffectiveFailureAction(config.RateLimitFailureAction),
   ```
2. [hard] Symmetry and consistency — `pkg/bouncer/bouncer_serve_ratelimit.go:66` — the captcha failure branch inlines `bypassesCaptcha` + `handleCaptchaKindServeHTTP(…ReasonRateLimit…)`, while the AppSec and ModSec failure actions route the same job through `captchaAppsecFailure` / `captchaModsecFailure` → `handleRemediationServeHTTP` (ban reason `LAPI` on a captcha downgrade); the sibling shapes and their downgrade reason now diverge
   Fix: Add `captchaRateLimitFailure` shaped like `captchaModsecFailure`; if the leg's own downgrade reason is the intended one, make the AppSec and ModSec helpers pass theirs too
   Status: done
   Argument: Extracted `captchaRateLimitFailure` (bypassCaptcha check, then the gate), dispatched like `captchaModsecFailure`. Kept the leg's own reason and `ratelimit-failure` header, which the bouncer spec names; aligning the AppSec/ModSec downgrade reason is outside this diff and not applied unattended.
3. [hard] One job, one owner — `pkg/ratelimit/charge.go:14` — the `Counter` interface (the counting contract `*Client` in `client.go` implements and `Bouncer` holds) is a distinct domain sharing `charge.go` with `Verdict`, `ExceededBucket` and `BucketSet.Charge`; no file is named for it
   Fix: Move `Counter` to `pkg/ratelimit/counter.go`
   Status: done
   Argument: `Counter` moved to `pkg/ratelimit/counter.go`.
4. [judgement] Duplicated Code — `pkg/ratelimit/bucket_set.go:71` — each row's predicates compile twice (alone in `compileBucket`, then the whole list at `bucket_set.go:56`), and `errors.Unwrap` peels httprule's `rule %d:` prefix, coupling the bucket error to httprule's wrap depth
   Fix: Let httprule export a one-rule compile without the index prefix and build the `Set` from those compiled rules, so each row compiles once and no `Unwrap` is needed
   Status: skipped
   Argument: judgement: the double compile runs once at startup and the bucket error stems are pinned by `TestNewBucketSet_rejectsEachRowError`; a one-rule compile export is a new httprule API, not taken unattended.
   Quote:
   ```
   if _, predicateErr := httprule.NewWithCatchAll([]httprule.Rule{rule.Rule}); predicateErr != nil {
   	return compiledBucket{}, errors.Unwrap(predicateErr)
   }
   ```
5. [hard] Leave a trail — `README.md:1327` — `ReclaimGraceSeconds` still says "a LAPI, AppSec, or ModSec connection"; the rate-limit Client is now a reclaim holder whose Redis sockets also stay open for that grace (`pkg/ratelimit/client.go` `Open`: "closes after the table grace")
   Fix: Add the rate-limit Redis connection to the `ReclaimGraceSeconds` description
   Status: done
   Argument: README `ReclaimGraceSeconds` now names the rate-limit Redis connection.
6. [hard] Leave a trail — `README.md:34` — says Traefik's `rateLimit` "counts per process and keys only on the source address or one header" (same claim in `openspec/changes/add-redis-rate-limit-leg/proposal.md:3`), but the Traefik v3.7 reference documents Redis-backed distributed counters (`redis.endpoints`, `redis.password`, `redis.db`, ...; in-memory per instance only without Redis) and a third `sourceCriterion`, `requestHost`
   Fix: Restate the difference against what Traefik documents (Redis option exists; source is IP, one header, or host) and name what only this plugin adds: named buckets with request predicates, multi-part keys (cookie, query, path capture, IP network), log-only buckets, CrowdSec drop metrics
   Status: done
   Argument: README.md:34 and proposal.md:3 now say Traefik's `rateLimit` can share counters through Redis but counts on one source (address, one header, or host), and name what the plugin adds.
   Note:
   ```
   Source: https://doc.traefik.io/traefik/reference/routing-configuration/http/middlewares/ratelimit/ (edit link points at the v3.7 branch), fetched 2026-11-21.
   ```
