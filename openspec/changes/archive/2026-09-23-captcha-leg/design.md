## Context

See proposal.md Why. Dest already publishes LAPI and AppSec through reclaim aliases (`plugin.go` `openOwned` / `claimOwned` / `Watch`, groups `lapi` / `appsec`). Captcha is still a local `*captcha.Client` built in `bouncer.New` from this router’s `BouncerCaptcha*`. Explore Decisions are accepted: third reclaim group `captcha` on the existing table; dest public keys; no local construct on bounce-only; header lifted off the shared client.

## Goals / Non-Goals

**Goals:**

- Same own / bounce axes as LAPI and AppSec: `captchaEnabled` owns, `bouncerEnabled` + `captchaInstanceName` bounces.
- Reuse `SetAlias` / `Watch` / `ClearPublisher`. Add `legCaptcha` cases; do not rewrite the two-leg helpers into a generic N-leg registry.
- Owner constructs the siteverify client, template, and gate. Subscribers Load only.
- Failure-action `captcha` gates on the effective instance name (after owner fill).

**Non-Goals:**

- A second slot table or `pkg/instance` rewrite.
- Renaming dest `bouncer*` / `lapi*` / `appsec*` back to spec `enabled` / `crowdsecLapiFailureAction`.
- Renaming `bouncerCaptcha*` to `captcha*`.
- Changing `crowdsec_captcha_gate` name or path, or a second cookie namespace.
- Blocking `New` until a captcha owner exists.
- Implicit own from a set provider.
- Writing `knowledge/devdocs` packets in this phase (Language deltas already shown; implement / `opd-devdocsimpact` fold them).

## Decisions

| Topic | Choice | Rationale |
|-------|--------|-----------|
| Slot identity | Reclaim group `captcha`, alias `alias:captcha:<name>` | Explore identity owner. Same table as LAPI/AppSec. `shared` may exist in all three. |
| Orchestration | Third case on `openOwned` / `claimOwned` / `Watch` | Explore seam. Do not invent an N-leg registry. |
| Public keys | New `captchaEnabled` / `captchaInstanceName`; bounce/failure stay `bouncer*` | Honor dest. Owner settings stay `bouncerCaptcha*`. |
| Empty name | `captcha.Prepare`: `captchaEnabled && trim(name)==""` → Traefik name | Copy LAPI’s explicit fill. |
| Ownership key | Middleware name plus instance-owned captcha knobs | Slot name, bounce, failure, header, startup-block stay off the key. |
| Holder | `Open` + `SetAlias` + `Watch`. Sleep/Wake MAY be no-ops | Holder with `bouncerEnabled: false` still Opens. No ticker. |
| Validation trigger | Owner checks only when `captchaEnabled` | No implicit own. Subscriber leftover keys ignored. |
| Failure-action gate | Effective captcha instance name after fill | Dest keys stay `bouncerLapiFailureAction` / `bouncerAppsecFailureAction`. |
| Missing client | No local fallback. Startup block on → 503. Off → captcha verdict bans | Same as today’s `!Valid`. |
| Header | Lift `remediationCustomHeader` off `captcha.Client` onto Bouncer call sites | Subscriber must not inherit the owner’s header. |
| Catalog | Fold the seven explore leaves; no new family | Live promises already live there. |

**Alternatives rejected:** implicit own from provider; block `New` until owner exists; reconstruct captcha on the subscriber when the slot is empty; rename dest bounce/failure keys; second cookie namespace; a second slot table.

## Risks / Trade-offs

- **Existing YAML that only sets `bouncerCaptchaProvider` stops owning captcha** → Default false, matching the other own flags. Update in-repo examples and e2e. README names the break.
- **Two captcha instances on one host still share `crowdsec_captcha_gate`** → Out of scope. A later solve overwrites the earlier cookie.
- **Shared siteverify idle pool** → Intended. `http.Client` and `template.Execute` are concurrent-safe; grace uses `time.Now()` per call.
- **Stale usage packets** still say captcha stays per-Bouncer → Enough to call the subsystems. Implement / `opd-devdocsimpact` fold them.

## Migration Plan

- Single-router operators set `captchaEnabled: true` (empty name fills to the Traefik name) and keep `bouncerCaptcha*` on that middleware.
- Split owners set `captchaEnabled: true` plus `captchaInstanceName`. Bouncing routers set `bouncerEnabled: true` plus the same name and leave `captchaEnabled` false.
- `bouncerLapiFailureAction: captcha` / `bouncerAppsecFailureAction: captcha` requires that router’s captcha instance name (after fill).
- Rollback is revert of the PR. Old provider-only YAML does not own captcha on the new binary.

## Open Questions

None. Explore rows stay as explore wrote them.
