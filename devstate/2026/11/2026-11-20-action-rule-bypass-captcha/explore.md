# Explore

## Concepts

Units this change touches:

- `httprule.ActionSet` — `pkg/httprule/action.go`. Parses the action tokens of each `bouncerActionRules` row (`compileActionTokens`) and reduces every matching row to one `ActionMatch` per request (`Fold`).
- `httprule.SingleReadingPath` — `pkg/httprule/path.go`. Says whether a request path has one reading. `Fold` uses it to drop the skips of a row with a `path` predicate. Not changed; `bypassCaptcha` does not consult it.
- LAPI leg — `pkg/bouncer/bouncer_serve_lapi.go`. Looks the client up, applies the per-origin remap (`appliedLAPIRemediation`), and remediates through `remediateWarnCaptchaRuleOnBan`. The LAPI failure action takes the same function.
- AppSec leg — `pkg/bouncer/bouncer_serve_appsec.go`, `bouncer_serve_appsec_verdict.go`. A `captcha` verdict and a captcha form POST go to `serveAppsecCaptchaGate`; the AppSec failure action `captcha` goes to `captchaAppsecFailure`.
- Captcha gate — `pkg/bouncer/bouncer_serve_captcha.go` `handleCaptchaKindServeHTTP`. Writes the challenge, the solved-form redirect, or the downgrade ban when this router has no usable captcha.
- Origin remap — `pkg/bouncer/origin_based_decision_remap.go`. One hop on the stored kind.

How a captcha is reached today (every arrow ends in the gate):

```
ServeHTTP ── fold rules ──> ActionMatch
   │
   ├─ serveLAPI ── decision / failure action ──> remediateWarnCaptchaRuleOnBan ──> handleRemediationServeHTTP ─┐
   │                                                                                                           │
   └─ serveAppSec ─┬─ captcha rule ──────────> applyCaptchaRuleServeHTTP ──────> handleRemediationServeHTTP ──┤
                   ├─ failure action captcha ─> captchaAppsecFailure ──────────> handleRemediationServeHTTP ──┤
                   ├─ captcha verdict ────────> serveAppsecCaptchaGate ─────────────────────────────────────────┤
                   └─ captcha form POST ──────> serveAppsecCaptchaGate ─────────────────────────────────────────┤
                                                                                                               ▼
                                                                                              handleCaptchaKindServeHTTP
```

Every caller already treats `false` from these functions as "nothing was written, continue". That is the return a bypassed captcha needs.

Call sites that matter (roots searched: `pkg/`, root `*.go`, tests included):

- `remediateWarnCaptchaRuleOnBan` — 3 callers, all in `bouncer_serve_lapi.go`.
- `captchaAppsecFailure` — 2 callers, both in `bouncer_serve_appsec.go`.
- `serveAppsecCaptchaGate` — 2 callers (`bouncer_serve_appsec.go`, `bouncer_serve_appsec_verdict.go`).
- `appliedLAPIRemediation` — 2 callers, both in `bouncer_serve_lapi.go`.
- `handleRemediationServeHTTP` — 4 production callers and 5 test callers. Not changed by the chosen seam.
- `ActionSet.Fold` — 1 production caller (`bouncer.go` `foldActionRules`), 6 test callers. `ActionMatch{}` literals: 10, all in tests, all keyed.

Reproduce: the behaviour the requirement describes was run on the dest tree's rule machinery in a real Traefik. Not a failure to reproduce but a premise to check: "Traefik already protects against path traversal in the URL". Path run 2026-11-20, Traefik v3.7.11 and v3.7.19, this plugin as a local plugin, rule `{path: "^/api/", action: [ban]}`, `curl --path-as-is`:

- Protected: `/api/../other`, `/api/%2e%2e/other`, `/api/.%2e/other`, `/api/..\other` arrive as `/other`; the rule does not match.
- Protected from v3.7.18 only: `/api/..;/other` (matches on v3.7.11, arrives as `/other` on v3.7.19).
- Not protected with default entry point options, on both versions: `/api/..%2Fother`, `/api/..%5Cother`, `/api/..%3B/other`, `/api/%252e%252e/other`. The rule matches and the backend receives the path unchanged.
- With `encodedCharacters.allowEncodedSlash`, `allowEncodedBackSlash`, `allowEncodedSemicolon` and `allowEncodedPercent` set to `false` on the entry point, Traefik answers `400` to those before the plugin runs.

Outside facts used: `knowledge/research/ext_traefik_entrypoints_request-path/` (written by this run, on this thread: the pack asks for a sub-agent, and the model `knowledge/opendev.json` names for sub-agents is not available in this client).

## Decisions

- Token name `bypassCaptcha`, parsed beside the other tokens in `compileActionTokens`. `captcha` and `bypassCaptcha` in one rule fail validation. `ban` already must be alone.
- `ActionMatch` gains `BypassCaptchaName` (first matching rule with the token; empty means none), the same shape as `BanName` and `CaptchaName`, so the trace can name the rule.
- When `BypassCaptchaName` is set, `Fold` returns an empty `CaptchaName`. A captcha rule of another row then never runs, and an AppSec `challenge` is still relayed (today a matched captcha rule answers in place of the challenge page; with no captcha to serve, the challenge must not be dropped).
- `Fold` reads the `bypassCaptcha` token before the single-reading check. A row that also carries `bypass*` tokens still loses those skips on an ambiguous path and still sets `AmbiguousPathName`.
- The bypass is asked through one predicate on the bouncer (named for the job, in `bouncer_serve_captcha.go`) at the three functions through which a captcha enters: `remediateWarnCaptchaRuleOnBan` (captcha kind only), `captchaAppsecFailure`, `serveAppsecCaptchaGate`. They return `false`, so the request continues to the next leg or to the backend. The predicate logs at TRACE with the rule name. No WARN: the condition is client-driven.
- The bypass comes before the "captcha unsubscribed" downgrade ban. A router without a usable captcha also lets the request through.
- `appliedLAPIRemediation` keeps a stored ban a ban when the remap would turn it into a captcha and the request bypasses captchas. A remap `ban: pass` still passes. A stored captcha is bypassed whether or not a remap exists.
- README: a section under "What you can do" for API routes, with one table of where the action applies and one of where it does not, the path-matching limits measured above, and the entry point options that close them. The `BouncerActionRules` reference gets the token and the path note.
- Rejected: the bypass inside `handleCaptchaKindServeHTTP`. It needs the match threaded through `handleRemediationServeHTTP` (4 production and 5 test callers) for one early return.
- Rejected: one check per captcha source in each leg (7 sites). Sibling paths would have to stay in step by hand.
- Rejected: a flag on `clientrequest.Request`. `knowledge/devdocs/core_plugin_middleware_action-rules.md` says not to put captcha or skip flags on the inbound request.
- Rejected: `bypass` implying `bypassCaptcha`. `[bypass, captcha]` is a documented combination today (skip both legs, then captcha).
- Live contract: `openspec/specs/core_plugin_middleware_bouncer` (fold, single-reading requirement), `openspec/specs/core_plugin_middleware_config-validation` (token validation), `openspec/specs/core_plugin_lapi_origin-based-decision-remap` (one hop at apply).

## Open questions

- Q: Does a ban that `bouncerOriginBasedDecisionRemap` softens to a captcha pass on a `bypassCaptcha` request?
  Rank: bounded asked — changes `appliedLAPIRemediation`, 2 call sites found in `pkg/` and root `*.go`, both migrated here; requirement Desired "a ban softened to a captcha … stays a ban".
  Decision: assumed — no, it stays a ban. Proposed in chat and not objected to; not in the caller's last message word for word.
  By: explore

- Q: Does a `bypassCaptcha` rule with a `path` use the single-reading path guard?
  Rank: additive asked — new token on a new branch of `Fold`; requirement Desired "applies its regex as written".
  Decision: resolved — no, by the caller's decision. The measurement shows the premise holds for `..`, `%2e%2e` and `\`, and for `..;` from Traefik v3.7.18, and does not hold by default for `%2F`, `%5C`, `%3B` and double encoding. The README states both lists and the entry point options that reject the second.
  By: explore

- Q: Does a LAPI or AppSec failure action `captcha` pass on a `bypassCaptcha` request?
  Rank: additive asked — new early return in functions whose `false` already means continue; requirement Desired "LAPI or AppSec failure action `captcha` pass".
  Decision: assumed — yes. During an outage these requests are let through, the same as failure action `passthrough`. The README says so.
  By: explore

- Q: What happens on a router with no usable captcha, where a captcha is served as a ban today?
  Rank: additive incidental — new early return before the downgrade ban; no requirement line names this case.
  Decision: assumed — the request passes. The decision was a captcha, and the rule says these requests get none; turning it into a ban would make the action depend on whether a captcha provider is configured.
  By: explore

- Q: What happens to a captcha form POST (challenge marker) on a `bypassCaptcha` request?
  Rank: additive incidental — same early return in `serveAppsecCaptchaGate`; no requirement line names this case.
  Decision: assumed — it reaches the backend like any other request. A path that never shows a captcha has no form to answer.
  By: explore

- Q: Is the AppSec bot-detection `challenge` covered?
  Rank: additive asked — no code on that path changes; requirement Desired "the AppSec bot-detection `challenge` is not covered".
  Decision: resolved — no. Its header value is `captcha:challenge`, so the README names it under "does not apply".
  By: explore

- Q: Which Traefik version may the README assume for the path behaviour?
  Rank: additive incidental — documentation only; no requirement line names a version.
  Decision: assumed — state what was measured (v3.7.11 and v3.7.19) and the documented version of the `..;` change (v3.7.18). Do not claim a minimum supported Traefik version.
  By: explore
