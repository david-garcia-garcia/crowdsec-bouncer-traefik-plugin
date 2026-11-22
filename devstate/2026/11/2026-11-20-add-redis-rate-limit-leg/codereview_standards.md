# Standards

1. [hard] std_go_logger_nested:36 — `pkg/bouncer/bouncer_leg_ratelimit.go:30` — the new rate-limit captcha ERROR lines pass `traefikName` again on `b.log`, which `bouncer.New` already built with `log.With("traefikName", name)`, so each line carries the key twice (same at `pkg/bouncer/bouncer_serve_ratelimit.go:172`)
   Fix: Drop `"traefikName", b.name` from both `msgRateLimitCaptchaUnavailable` calls; keep `reason`, `instanceName`, and `captchaInstanceName`
   Status: done
   Argument: Dropped `"traefikName", b.name` from both ERROR calls; `bouncer.New` adds it with `log.With` (pkg/bouncer/bouncer.go:65). Literal test routes in zzz_rate_limit_captcha_test.go now build their sink logger with `With("traefikName", name)` (2a196881).
   Quote:
   ```
   b.log.Error(msgRateLimitCaptchaUnavailable,
   	"reason", "unsubscribed", "traefikName", b.name, "instanceName", b.rateLimitLeg.instanceName)
   ```
2. [hard] Leave a trail — `pkg/lapi/client_metrics.go:31` — `OriginPluginRateLimitPrefix` still says "rate-limit bucket denied", but this round made the same prefix the origin of a captcha bucket's challenge too (the `OriginPluginRateLimit` doc was updated, the prefix comment was not)
   Fix: Reword the trailing comment to "rate-limit bucket answered (ratelimit or captcha)"
   Status: done
   Argument: Comment now reads "rate-limit bucket answered (ratelimit or captcha)" (2a196881).
   Quote:
   ```
   OriginPluginRateLimitPrefix   = "plugin:ratelimit:"         // rate-limit bucket denied
   ```
3. [hard] Leave a trail — `pkg/ratelimit/bucket_set.go:124` — the `compileBucketAction` comment says "(the round-1 deny included)": "round-1" is a review-round label of this ticket that a later reader of the product tree cannot decode
   Fix: Say "(the former `deny` value included)" or drop the parenthetical
   Status: done
   Argument: Comment now says "(the former deny value included)" (2a196881).
4. [judgement] Feature Envy — `pkg/bouncer/bouncer_serve_ratelimit.go:63` — `serveRateLimit` takes `client.Buckets()` and then hands `client` back to it as the Counter (`buckets.Charge(ctx, client, …)`); the only production `Charge` caller walks the Client's own buckets with the Client's own counter, so the bouncer depends on how the Client splits buckets from counter
   Fix: Add `(*ratelimit.Client).Charge(ctx, middlewareName, httpReq, clientIP, gateCleared)` that calls `c.buckets.Charge(ctx, c.counter, …)`, and call that from `serveRateLimit`; keep `BucketSet.Charge` for the fake-counter tests
   Status: skipped
   Argument: judgement; a `Client.Charge` wrapper is a new API on `pkg/ratelimit` for a single caller, and `BucketSet.Charge` already takes any Counter so tests and the Yaegi program use fakes. Not applied unattended.
   Quote:
   ```
   buckets := client.Buckets()
   ...
   verdict := buckets.Charge(ctx, client, b.name, req.Request, req.IPAddr(), gateCleared)
   ```
5. [judgement] Mysterious Name — `pkg/bouncer/leg_binding.go:15` — the `legBinding` string field `leg` holds the leg's reclaim group name, which `publishedLeg` (`plugin.go:52`), added in the same round, calls `group`; inside a type called legBinding, `binding.leg` reads as the leg itself, and the two sides of one leg spell the same role differently
   Fix: Rename `legBinding.leg` to `group` (comment: reclaim group and trace "leg" attr), matching `publishedLeg.group`
   Status: skipped
   Argument: judgement; renaming `legBinding.leg` touches every binding literal and the lifecycle tests for no behaviour change, and the field is the trace `leg` attribute it is named after. Not applied unattended.
