# Bouncer action rules (local)

IssueKey: 2026-09-29-bouncer-action-rules
issueHost: local
issueRef: none

Breaking change. Retire public config `bouncerAppsecBypassRules`, `bouncerLapiBypassRules`, and `bouncerDecisionHeader`. Replace them with one list, `bouncerActionRules`.

Each rule keeps the existing request predicates (`method`, `path`, `host`, `headers`, `cookies`: omitted means any; set predicates AND; Go RE2 unanchored; method may have a single leading `!`; empty header or cookie pattern means that name is present; header names case-insensitive; cookie names case-sensitive; fully empty predicates still fail `New`, including `method: ".*"` as any). Add:

- `name` — required, unique in the list, must not contain `:`.
- `action` — a required non-empty array. Tokens: `bypass`, `bypassLapi`, `bypassAppsec`, `ban`, `captcha`. Order in the array does not matter. `bypass` is sugar for skipping both LAPI and AppSec. Duplicates, unknown tokens, an empty array, or an omitted action fail `New`. `ban` must be the only token in that array; `ban` combined with `captcha` or any skip fails `New`. The action array is not a match predicate.

All matching rules contribute. This is not first-match-wins. List order only picks the name when two rules share the same winning remediation.

Effects:

- Any matching `ban` → immediate ban. LAPI and AppSec do not run. Metrics origin `plugin:rules:<name>` where `<name>` is the first matching ban rule. `remediation=ban`. A bypass on another matching rule does not weaken this ban.
- Otherwise fold every match: `bypass` or `bypassLapi` skips LAPI; `bypass` or `bypassAppsec` skips AppSec; any `captcha` token sets a soft captcha flag. Skips add; they never cancel each other or a captcha flag.
- `captcha` does not return immediately. Legs that were not skipped still run. An active LAPI ban, or a fail-closed ban from that leg (lookup error, stream/alone unhealthy, failure action `ban`), prevails over the captcha rule. An AppSec `ban` verdict, or an AppSec failure-action `ban`, prevails over the captcha rule. Those drops keep the leg's own origin, not `plugin:rules:`. Log a warning that names the captcha rule that lost (same situation as today's `ServeHTTP:forcedCaptchaSuperseded`).
- An AppSec `challenge` is not a ban and does not override the captcha rule.
- A CrowdSec captcha decision is unchanged: the rule does not replace that outcome, the metrics origin stays the CrowdSec origin, and AppSec for that decision stays where it is today (after a valid captcha gate cookie, not before the challenge page).
- If no leg banned and a captcha rule matched, serve the existing captcha gate. Origin `plugin:rules:<name>` of the first matching captcha rule, `remediation=captcha`, only when that rule is what is applied. A valid gate cookie still passes. After the cookie is valid, AppSec still runs unless a matching `bypass` or `bypassAppsec` skipped it.
- The only way for a captcha rule to avoid a LAPI ban is a matching `bypass` or `bypassLapi` (same rule or another matching rule). The only way to avoid an AppSec ban is a matching `bypass` or `bypassAppsec`. Example: one rule with `action: [captcha, bypass]` skips both legs and then captchas. `[captcha, bypassLapi]` still allows AppSec to ban. `[captcha]` alone allows both legs to ban.
- Captcha with no usable captcha client does not fail `New`. It downgrades to a ban at request time with the existing `crowdsec bouncer captcha unsubscribed` warning. That drop's origin is still `plugin:rules:<name>`, `remediation=ban`.
- Skips do not increment `dropped`. `recordProcessed` still runs.
- Rules run after startup block, `GetRemoteIP` (failure still tech-bans), and the trusted-IP skip. Trusted clients never hit these rules. A failed client-IP parse is not saved by a bypass rule.
- Delete the decision-header helpers (`forcedDecisionKind`, `passOrForcedCaptcha`, `remediateOrForcedCaptcha`, `banOrWarnForcedCaptcha`). Nothing after lookup merges a secret `b` or `c`.
- The old header is expressed as rules. Header match is unanchored RE2 against each value, so the patterns must be anchored (`^b$`, `^c$`), not a bare `b`. `[captcha]` keeps today's "LAPI ban beats header c" outcome. `[captcha, bypassLapi]` is a stronger choice and is not the old header.
- These rules must not enter LAPI ownership keys or AppSec identity keys.
- Compile once off the request path (`ValidateParams` and again in `bouncer.New`, same split as the bypass lists). Do not compile per request.
- Traefik drops unknown keys before the plugin sees them, so leftover `bouncerAppsecBypassRules`, `bouncerLapiBypassRules`, and `bouncerDecisionHeader` cannot fail `New` and cannot be warned on. Document that break.

Example:

```yaml
bouncerActionRules:
  - name: healthz
    path: "^/healthz$"
    action: [bypass]
  - name: decision-ban
    headers:
      X-Crowdsec-Decision: "^b$"
    action: [ban]
  - name: decision-captcha
    headers:
      X-Crowdsec-Decision: "^c$"
    action: [captcha]
  - name: challenge-health
    path: "^/healthz$"
    action: [captcha, bypass]
```
