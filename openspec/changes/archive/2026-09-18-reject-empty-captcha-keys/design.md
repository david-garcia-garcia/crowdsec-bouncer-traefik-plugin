## Context

See proposal.md — Why. `validateCaptchaCredentials` already calls `GetVariable` for site and secret and returns only lookup errors. `CaptchaGateSecret` on the same provider-set path already rejects `""` after lookup. `GetVariable` is file then field, trimmed; it does not read the environment. `New` already returns `nil, err` when `ValidateParams` fails.

## Goals / Non-Goals

**Goals:**
- Reject empty trimmed site and secret after a successful `GetVariable`, independently, site first.
- Same trigger as the gate secret: `CaptchaProvider != ""`.
- Keep lookup errors. Reuse `GetVariable`. Leave `New` as `return nil, err`.

**Non-Goals:**
- A new env lookup.
- Empty `CaptchaGateSecret` (already rejected).
- Template, custom-challenge URL, routing, gate, or provider HTTP changes.
- Other `ValidateParams` rules.

## Decisions

1. Owner is `validateCaptchaCredentials`. After each successful `GetVariable`, reject `""` for that field. Site before secret. Alternative: check after both lookups — rejected; first-fail matches the gate secret and names the empty field.
2. Reuse `GetVariable`. Do not add `Getenv`. Alternative: ticket “file/env” wording — rejected; requirement out of scope and `GetVariable` has no env today.
3. Error text matches the gate secret: `CaptchaSiteKey: cannot be empty when CaptchaProvider is set` (and the secret twin).
4. Tests stay in `zzz_configuration_test.go`. Keep one provider-present success case by giving it dummy site and secret. Empty-key fixtures want an error (including default `ban`). Custom-challenge fixtures that set a provider get dummy keys so they still test URL rules. `New` regression in `zzz_plugin_test.go` stops at validation (no LAPI Open).

## Risks / Trade-offs

- [Startups that set a provider without keys now fail] → intended fail-closed. Operators who already set both keys are unchanged.
- [Existing “Captcha LAPI action with provider” success fixture becomes an error] → give it non-empty site and secret; the empty-key case is a new error row.

## Migration Plan

None. Validation-only. Roll back by reverting the empty-string checks.

## Open Questions

None — ticket decisions stand on `explore.md`.
