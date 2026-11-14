## Context

`applyAppsecServeHTTP` maps an AppSec verdict to a response: `ban` → ban page, empty `challenge` → ban page, everything else → `handleAppsecResponseServeHTTP`, which writes the envelope's status, headers, cookies and body. That relay is right for `challenge` (CrowdSec sends a full page) and wrong for `captcha` (CrowdSec sends `action` and `http_status` only; source `crowdsecurity/crowdsec@e20782bb:pkg/appsec/appsec.go` `GenerateResponse`). Research: `knowledge/research/ext_crowdsec_appsec_protocol/`.

The router already owns a captcha gate (`handleRemediationServeHTTP` → `handleCaptchaKindServeHTTP`) used by LAPI captcha decisions, captcha action rules and AppSec failure-action captcha: HMAC gate cookie, challenge-marker leftover redirect, downgrade ban when no usable client.

## Goals / Non-Goals

**Goals:** serve the router captcha for an AppSec `captcha`; never write an empty page for a bodyless AppSec action; keep the captcha solvable when AppSec allows the form POST.

**Non-Goals:** per-source solved state (lua keeps LAPI and AppSec apart); validating the submission before AppSec (lua); AppSec 429 handling (separate review item); `/crowdsec-internal/challenge/*` termination; any Config key.

## Decisions

1. **AppSec `captcha` → captcha gate.** `applyAppsecServeHTTP` calls the captcha gate with origin `appsec`, header reason `appsec`, downgrade template reason `APPSEC`. `handleCaptchaKindServeHTTP` takes the header reason and the downgrade ban reason from its caller instead of deriving them; `handleRemediationServeHTTP` keeps passing `headerReasonFromOrigin(origin)` and `ReasonLAPI`, so every existing caller is unchanged. Not using `headerReasonFromOrigin("appsec")`: that would map to `lapi` with a third field.
   Alternative rejected: ban page (review's minimal step) — the protocol assigns `captcha` to the bouncer's captcha and the router has one.
2. **Captcha rule wins the gate.** With `match.CaptchaName` set, AppSec `captcha` returns false so `applyCaptchaRuleServeHTTP` serves the rule gate (origin `plugin:rules:<name>`), same as non-empty `challenge`.
3. **Bodyless unknown action → ban.** Unknown action with empty `user_body_content` → `handleBanServeHTTP` with header reason `appsec-action-empty`, origin `appsec`. Bodied unknown actions keep relaying (no CrowdSec version produces one; the relay contract stays). Mirrors lua's fallback and the fork's LAPI handling of unknown decision types (#198).
4. **Challenge-marker POST after AppSec.** In `serveAppSec` (non-rule path), when `applyAppsecServeHTTP` did not write and the request is a POST carrying `crowdsec_captcha_challenge=v1` (`HasChallengeMarker`, 64KiB peek, body restored on no) on a router whose captcha client is subscribed, published and Valid, call the same captcha gate. First solve validates the token; a cleared gate gets the solved redirect. AppSec already inspected the POST, so its bans still apply.
   Alternative rejected: validate before AppSec (lua) — the POST would skip the WAF.
   Alternative rejected: rely on AppSec answering the POST with `captcha` again (upstream #403) — a rule keyed on the GET body, method or a path the form does not repeat leaves the captcha unsolvable and forwards the solve POST to origin.
5. **One gate cookie for every source.** Solving any captcha on the router clears the AppSec captcha for the gate grace period, as LAPI, rule and failure-action captchas already share it (and as upstream does). The routing doc forbids a server-side grace cache.

## Risks / Trade-offs

- [A marker POST no longer reaches origin on routers with AppSec and a usable captcha client] → only the shipped challenge pages emit the marker; documented in README and the routing usage doc.
- [Custom challenge template without the marker] → falls back to upstream behavior: solvable only when AppSec answers the POST with `captcha`. README already tells operators to keep the marker.
- [Solved captcha also clears AppSec captcha] → bounded by the gate grace period; AppSec `ban` still applies after the gate.
- [No real-stack proof] → envelope shape settled from CrowdSec source; mock e2e proves the plugin side.

## Migration Plan

No Config change. Operators who relied on `captcha:appsec` meaning a relayed envelope now see the router captcha page under the same header value.

## Open Questions

None beyond `devstate` explore rows.
