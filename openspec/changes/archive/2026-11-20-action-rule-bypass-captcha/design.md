## Context

See proposal.md and `devstate/` explore. Every captcha this router serves is written by `handleCaptchaKindServeHTTP`, and every caller already reads `false` from the functions around it as "nothing was written, continue". A bypassed captcha is that same return.

## Decisions

1. **Token and fold in `httprule`.** `bypassCaptcha` is parsed beside the other tokens. `ActionMatch.BypassCaptchaName` names the first matching row, the same shape as `BanName` and `CaptchaName`, so the TRACE can name the rule. `httprule` keeps importing only the standard library.
2. **`Fold` clears `CaptchaName` when the bypass is set.** A matched captcha rule answers in place of an AppSec `challenge` page today. With no captcha to serve, a leftover `CaptchaName` would drop the challenge. Clearing it in `Fold` keeps one reading of the match for every leg.
3. **`Fold` reads `bypassCaptcha` before the single-reading check.** The skips of the same row are still dropped on an ambiguous path and `AmbiguousPathName` is still set.
4. **One predicate, three entry functions.** `bypassesCaptcha(req, match)` in `bouncer_serve_captcha.go` is asked by `remediateUnderActionRules` (captcha kind only; renamed from `remediateWarnCaptchaRuleOnBan`, whose name no longer covered its job), `captchaAppsecFailure`, and `serveAppsecCaptchaGate`. They return `false`. Alternative: decide inside `handleCaptchaKindServeHTTP` — rejected, it needs the match threaded through `handleRemediationServeHTTP` (4 production and 5 test callers) for one early return. Alternative: a check per captcha source in each leg (7 sites) — rejected, sibling paths would have to stay in step by hand. Alternative: a flag on `clientrequest.Request` — rejected, the action-rules usage doc says not to put captcha or skip flags on the inbound request.
5. **The bypass comes before the downgrade ban.** The decision was a captcha and the rule says these requests get none. Banning when no captcha provider is configured would make the action depend on unrelated configuration.
6. **Remap exception in `appliedLAPIRemediation`.** It already owns "stored kind to applied kind" for both lookup paths. It takes the match and keeps a stored ban when the remap would give a captcha and the request bypasses captchas.
7. **TRACE, not WARN.** The condition is client-driven; a WARN would let any client fill the log.
8. **No single-reading check for this token.** Caller decision. Measured on Traefik v3.7.11 and v3.7.19: `..`, `%2e%2e` and `\` are resolved before the plugin; `..;` from v3.7.18; `%2F`, `%5C`, `%3B` and double encoding are forwarded unless the entry point rejects them (`encodedCharacters`). The README states both lists.

## Risks

- A client under a captcha can reach a non-exempt resource without the captcha when all three hold: the path leaves the rule's prefix through an encoded `/`, `\` or `;` (or double encoding), the Traefik entry point allows that encoding (the default), and the backend resolves it. Bans are not affected. Mitigation: documented, with the entry point options that reject those requests.
