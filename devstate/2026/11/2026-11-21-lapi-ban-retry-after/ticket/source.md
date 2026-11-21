# Source (issueHost: local)

## Human ask (2026-11-21, chat)

"could we add retry-after for banned lapi bans? https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/439"

## Reference

Upstream PR maxlerebourg/crowdsec-bouncer-traefik-plugin#439, "✨ send Retry-After with LAPI bans answered 429" (state `open`, not merged, created 2026-11-17, last updated 2026-11-17; read 2026-11-21 via the GitHub host). Upstream design, from its description:

- When `remediationStatusCode` is 429, a ban from a LAPI decision carries `Retry-After` = seconds left on the decision, rounded up, minimum 1. No header with any other status.
- AppSec 429s carry no `Retry-After` (AppSec sends no time).
- live/none: the end is the latest among the blocking decisions LAPI returns (bans, plus captchas when no captcha provider is set).
- live-mode cached ban keeps the decision end, not the cache-entry end (the entry still lasts at most `defaultDecisionSeconds`).
- Cache format upstream: `t;<unix ms>`; entries from earlier versions have no end and get no header; the end is the writing instance's clock (replica clock skew).
- Upstream layout (`pkg/cache`, root `bouncer.go`) does not exist in this fork. The fork uses `pkg/decisionstore` (packed memory slots `LiveSlot{Word uint32, ExpiresAt int32}` on an elapsed clock, Redis `kind\norigin\nscenario` values with MSetEX TTL, a Range-index blob with no per-entry end), `pkg/bouncer` serve paths (`bouncer_serve_lapi.go`, `bouncer_serve_remediation.go`), and `pkg/lapi` (`client_live.go`, `client_decisions.go`, stream apply).

## Decisions taken with the human in chat (2026-11-21)

1. Send `Retry-After` only when the final response is a ban that comes from a LAPI decision with a known end AND the status written is 429 (`bouncerRemediationStatusCode: 429`). No header with 403 or other codes, none on AppSec bans (including AppSec `http_status` 429), none on technical/failure-action bans (LAPI unreachable, cache/Redis failure, unhealthy stream).
2. Live mode must report the REAL remaining time of the decision, not the cache-entry TTL (capped at `defaultDecisionSeconds`). The human explicitly approved growing the memory `LiveSlot` from 8 to 12 bytes (adding a decision-end field), which changes the rule in `knowledge/devdocs/core_plugin_decisionstore.md` that says LiveSlot stays 8 bytes.
3. Redis: carry the decision end as an additional field in the stored value so it survives cache hits across instances; it must stay readable by previous fork versions (older `unpackFromString` reads kind and origin correctly with an extra field; scenario is unused on the Redis lookup path). Rolling upgrade / rollback safe.
4. Range-scope bans: the Range-index blob has no end; proposed by the assistant, not objected to: Range bans carry no `Retry-After` in this change and the README says so.
5. When several decisions hit, use the end of the decision that produced the ban (a short value only makes the client come back early and get a fresh header; it can never be too long).
6. Implement now, in this fork, independently of upstream merging #439. Delivery via opd-workflow full run, PR to `master`, with unit tests, e2e mock and real e2e coverage for 429 + `Retry-After` where the existing suites allow.
7. Must interact correctly with `bouncerActionRules` (captcha→ban, bypassCaptcha), origin-based decision remap, and unsubscribed-captcha-served-as-ban; README documents the header next to `bouncerRemediationStatusCode`.
