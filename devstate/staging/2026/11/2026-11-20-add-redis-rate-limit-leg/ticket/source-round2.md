# Caller spec addendum — 2026-11-20-add-redis-rate-limit-leg, round 2 (2026-11-21)

Same ticket, same branch, same PR #228. The first round (rate-limit leg, `deny | log`) is implemented, reviewed,
its OpenSpec change `add-redis-rate-limit-leg` archived and synced. This round changes the bucket actions.

## Human ask (verbatim, chat 2026-11-21)

> can we not have an action for each bucket, such as "ratelimit" or "captcha" (ratelimit is the response=

The conductor proposed (chat):

| `action` | Response | Verdict header |
|---|---|---|
| `ratelimit` (default) | `rateLimitStatusCode` (429) + `Retry-After` | `ban:ratelimit:<bucket>` |
| `captcha` | the plugin's captcha page; a client that has solved it gets through | `captcha:ratelimit:<bucket>` |
| `log` | lets the request through, only logs at INFO | — |

- Rename `deny` → `ratelimit`. PR #228 is unmerged, so `deny` has no users: rename, no alias.
- Bucket `captcha` reuses the captcha path the failure action already uses (`captchaRateLimitFailure` in
  `pkg/bouncer/bouncer_serve_ratelimit.go`: gate, widget assets, cleared gate, bypassCaptcha).
- Hard ceiling = stacking: a `captcha` bucket plus a `ratelimit` bucket on the same key
  (e.g. per-ip-soft 300/min captcha, per-ip-hard 1200/min ratelimit). No new fields.

Example the human saw:

```yaml
rateLimitBuckets:
  - name: per-ip-soft
    requests: 300
    window: 1m
    action: captcha
    key:
      - from: ip
  - name: per-ip-hard
    requests: 1200
    window: 1m
    action: ratelimit
    key:
      - from: ip
  - name: per-network
    requests: 5000
    window: 1m
    action: log
    key:
      - from: ip
        ipv6Prefix: 64
```

## Human decisions (verbatim answers, chat 2026-11-21) — these are DECIDED, not assumed

> 1. Correct, it reuses cptchaGracePeriodSeconds
> 2. ok
> 3. I prefer a resiilent plugin, instead of what you proposed, use a downgrade but log an ERROR.
> 4. No counting while exempt
> 5. true
>
> Implement

Meaning of each, against the questions the conductor asked:

1. **Captcha session lifetime:** a solve lasts the existing captcha session, `captchaGracePeriodSeconds`. No new setting.
2. **API routes with `bypassCaptcha`:** a bucket with `action: captcha` acts as `ratelimit` (429 + Retry-After,
   verdict `ban:ratelimit:<bucket>`) on requests that a `bypassCaptcha` rule matches. Differs on purpose from
   `bypassCaptcha` elsewhere ("let it through"): a rate limit must not become unlimited.
3. **`action: captcha` on a router without a captcha:** do NOT fail at startup. Downgrade at request time using
   the existing downgrade path (`ban:captcha-downgrade` style — serve the ban/429 instead), and log at ERROR.
   Resilience over strictness. (Decide in explore/propose: status code of the downgrade — the bucket's
   `rateLimitStatusCode` 429 + Retry-After is the natural reading for a rate-limit bucket; and log rate — an ERROR
   per request may flood; the owner's standing rule for gates is "log on transitions, never per request", so
   consider once-per-bucket/at-startup ERROR plus DEBUG per request, and record the choice.)
4. **Counting while exempt:** a client that has solved the captcha (valid gate within captchaGracePeriodSeconds)
   is NOT counted by `captcha` buckets. It is still counted by `ratelimit` and `log` buckets.
5. **Captcha traffic:** the captcha page's own requests (widget assets, verification POST) must never be counted
   or blocked by any bucket. Needs a real-stack e2e test.

Also in scope (conductor proposal, accepted with "Implement"): real-stack e2e covering captcha → solve → hard 429
on stacked buckets, using the stack's existing captcha test provider setup (see #223/#226 e2e for how captcha is
solved in Pester).

## Housekeeping

- The debt note `knowledge/debt/2026-11-20-rate-limit-captcha-action.md` and its issues.md row are taken by this
  round: close the row and delete the debt file when this lands (per opd-workflow § Issues).
- README "Limits of this version" currently says `action: captcha` fails at startup — must change.
- The open-question row "captcha action out of scope" (explore) is now decided by the human.
