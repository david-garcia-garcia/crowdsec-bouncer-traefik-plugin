# Nitpicks

1. [hard] Name for the scope — `pkg/bouncer/bouncer_serve_ratelimit.go:40` — `serveRateLimit` holds two leg clients and names only one of them: `client` (rate limit) beside `captchaClient`, so `buckets.Charge(ctx, client, …)` and the `client == nil` guard make the reader check which client is meant; the sibling serve methods name the leg (`lapiClient`, `appsecClient`)
   Fix: Rename the local to `rateLimitClient` in `serveRateLimit`, and the parameter `client *ratelimit.Client` of `answerRateLimitChallengeForm` (line 95) to `rateLimitClient`, because that body also sends the request to the captcha gate
   Status: done
   Argument: `client` renamed `rateLimitClient` in `serveRateLimit` and `answerRateLimitChallengeForm` (2a196881).
   Quote:
   ```
   client := b.loadedRateLimit()
   if client == nil || match.SkipRateLimit {
   	return false
   }
   captchaClient := b.usableCaptcha()
   ...
   verdict := buckets.Charge(ctx, client, b.name, req.Request, req.IPAddr(), gateCleared)
   ```
2. [hard] Name for the scope — `pkg/ratelimit/charge.go:45` — `Charge` uses the bouncer's term for its new parameter (`gateCleared`, "holds this router's valid captcha gate"). Inside `pkg/ratelimit` this body only uses it to skip captcha buckets, and the package has no gate
   Fix: Rename the parameter to `skipCaptchaBuckets` (or `captchaSolved`) in `Charge` and its doc. The caller's local `gateCleared` in `serveRateLimit` stays and is passed as the argument
   Status: done
   Argument: `Charge` parameter renamed `skipCaptchaBuckets` with its doc; the caller keeps `gateCleared` (2a196881).
   Quote:
   ```
   func (set *BucketSet) Charge(ctx context.Context, counter Counter, middlewareName string, httpReq *http.Request, clientIP net.IP, gateCleared bool) Verdict {
   ...
   		// A solved client is not counted by captcha buckets.
   		if gateCleared && bucket.action == ActionCaptcha {
   			continue
   		}
   ```
3. [hard] Name for the scope — `pkg/ratelimit/charge.go:91` — new helper `wholeSecondsAtLeastOne` uses the placeholder parameter `d`, but the doc and its only caller pass the counter's RetryAfter
   Fix: Rename `d` to `retryAfter`
   Status: done
   Argument: `d` renamed `retryAfter` (2a196881).
   Quote:
   ```
   func wholeSecondsAtLeastOne(d time.Duration) time.Duration {
   	if d <= time.Second {
   		return time.Second
   	}
   	return (d + time.Second - 1).Truncate(time.Second)
   }
   ```
4. [hard] Name for the scope — `pkg/bouncer/leg_binding.go:35` — in `traceBinding`, `current` and `previous` are incarnation strings, not Clients. The block comments still say "Release the previous Client" and "Bind the new Client", so `current == ""` and `previous != ""` read as nil checks on a Client. The reader has to know that an empty incarnation stands for nil
   Fix: Rename to `currentIncarnation` and `previousIncarnation`, keeping the stem of the field `tracedIncarnation`
   Status: done
   Argument: `current`/`previous` renamed `currentIncarnation`/`previousIncarnation` in `traceBinding` (2a196881).
   Quote:
   ```
   func (b *Bouncer) traceBinding(binding *legBinding, current string, onBind func()) {
   	...
   	previous := binding.tracedIncarnation
   	binding.tracedIncarnation = current
   	...
   	// Release the previous Client, if any.
   	if previous != "" && previous != current {
   ```
5. [hard] Clear conditions — `pkg/bouncer/leg_binding.go:46` — `previous != current` in the release guard can never be false at that point. When `traceSeen` is true and `current == tracedIncarnation`, the method already returned. When `traceSeen` is false, `previous` is `""` and the first clause already fails. The extra clause sends the reader looking for a case that does not exist
   Fix: `if previous != "" {` (the same behaviour, shown by the early return above it)
   Status: done
   Argument: Release guard is now `if previousIncarnation != ""` with a comment that the same incarnation returned above (2a196881).
   Quote:
   ```
   	if binding.traceSeen && current == binding.tracedIncarnation {
   		return
   	}
   	previous := binding.tracedIncarnation
   	binding.tracedIncarnation = current
   	binding.traceSeen = true

   	// Release the previous Client, if any.
   	if previous != "" && previous != current {
   		b.traceBouncerBinding(false, binding.leg, binding.instanceName, previous)
   	}
   ```
