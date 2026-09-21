# Explore
IssueKey: 2026-09-18-captcha-empty-keys-accepted

## Concepts

`ValidateParams` always runs captcha credential/template checks when `BouncerCaptchaProvider` is set (`validateEnabledCaptchaSettings`), including `lapiMode: alone`. Alone only skips LAPI URL/key/TLS after CAPI file/field lookup. `plugin.go` `New` already returns `nil, err` on `ValidateParams` failure — no handler.

`GetVariable` is `*File` then the config field. It trims. It does not read the environment (`pkg/configuration` has no `Getenv`). An empty resolved string is `("", nil)`.

`validateCaptchaCredentials` discards those strings and returns only lookup errors. `BouncerCaptchaGateSecret` on the same path already rejects `""` after lookup. Site and secret do not.

```
BouncerCaptchaProvider set
        │
        ▼
GetVariable(site) ── lookup err ──► return
        │ ""
        ▼
GetVariable(secret) ── lookup err ──► return
        │ ""
        ▼
GetVariable(gate) ── "" ──► error (today)
        │
        ▼
optional BouncerCaptchaFile template
```

Spec `core_plugin_middleware_config-validation` scenario **Alone mode missing captcha keys**: alone + captcha failure action + provider + empty site/secret → `ValidateParams` error.

Usage packets: `core_plugin_middleware.md` covers `New` / reclaim, not this empty-key rule. `core_plugin_middleware_captcha-gate.md` requires a gate secret when a provider is set; it does not say site/secret must be non-empty after lookup. That is enough to call the existing empty-check pattern (`BouncerCaptchaGateSecret`). No new packet this phase — the desired contract is not on DestBranch yet. No third-party research write: this is our `ValidateParams`, not provider HTTP or Traefik `New` lookup.

This work does not set or reconstruct client address, user, tenant, Host, or a trust hop.

## Decisions

1. **Owner** — fix `validateCaptchaCredentials`. Keep lookup errors. After a successful `GetVariable`, reject `""` for site and for secret, independently, site first. Same trigger as the gate secret: `BouncerCaptchaProvider != ""`, not “failure action is captcha”.
2. **Lookup** — reuse `GetVariable`. Do not add env.
3. **Messages** — same shape as the gate secret: `BouncerCaptchaSiteKey: cannot be empty when BouncerCaptchaProvider is set` (and the secret twin).
4. **`New`** — leave `return nil, err`. Add a regression that stops at validation (no LAPI Open).
5. **Tests** — existing `zzz_configuration_test.go` table. Hunt names are not in this tree.

## Open questions

- Q: The ticket says reject empty keys after file/env lookup. `GetVariable` is file then config field only. Add env?
  Decision: assumed — do not add env lookup. Requirement out of scope: “A new env lookup beyond GetVariable”.
  By: explore

- Q: Reject empty site/secret only when a failure action is `captcha`, or whenever `bouncerCaptchaProvider` is set?
  Decision: resolved — whenever `BouncerCaptchaProvider` is set. Matches `BouncerCaptchaGateSecret` and the requirement text. Spec scenario is one case of that rule.
  By: explore

- Q: After the fix, should “Captcha LAPI action with provider” stay a success case?
  Decision: assumed — keep one provider-present success case by giving it non-empty site and secret. Empty-key fixtures must want an error (including default `ban` action).
  By: explore

- Q: What error text, and in what order?
  Decision: assumed — first-fail, site then secret, same wording as `BouncerCaptchaGateSecret: cannot be empty when BouncerCaptchaProvider is set`.
  By: explore

- Q: Hunt tests `TestHunt_newRejectsEnabledCaptchaWithoutSiteKey` and `TestHunt_ValidateParams_aloneMissingSiteKeysWithGateSecret` are named in the ticket.
  Decision: resolved — not in this tree (grep `func TestHunt_`). Implement adds equivalent coverage in `zzz_configuration_test.go` and a `New` validation-fail case in `zzz_plugin_test.go`.
  By: explore

- Q: `Test_validateEnabledCaptchaSettings_customChallengeURL` (and similar) set a provider and gate secret with empty site/secret and currently pass.
  Decision: assumed — give those fixtures dummy site and secret so they still test challenge-URL / custom-field rules.
  By: explore

- Q: Whitespace-only keys or an empty key file — accept or reject?
  Decision: resolved — reject. `GetVariable` already trims; `("", nil)` is empty.
  By: explore

- Q: Only one of site or secret empty?
  Decision: assumed — reject that field. Do not require both to be empty before erroring.
  By: explore

- Q: Where does the `New` nil-handler regression live?
  Decision: assumed — `zzz_plugin_test.go` `TestNew_*` that sets provider + gate secret + empty keys and asserts `handler == nil` and `err != nil`. Stops before LAPI Open.
  By: explore
