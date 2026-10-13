## Context

See proposal.md Why. Public `Config` JSON tags and Go fields still use `crowdsec*` / unprefixed names. `EffectiveHTTPTimeoutSeconds` inherits a shared `httpTimeoutSeconds`. LAPI identity JSON still prefixes `Lapi*` while AppSec already dropped that prefix. Explore Decisions are accepted: rename at `Config`, drop the prefix at the owning package, three independent timeouts `>= 1`, fold the eleven live leaves, reuse existing marshalers.

## Goals / Non-Goals

**Goals:**

- One mechanical rename of public keys and the Go fields that carry them.
- Drop the domain prefix at `pkg/lapi` (match AppSec) and keep local names on `Bouncer` / `pkg/captcha`.
- Delete inherit timeout. Wire each client from its own knob.
- Reuse `pkg/lapi/identity.go` and `pkg/appsec/session.go` as the only hash owners.

**Non-Goals:**

- Old-key aliases or nested YAML.
- A second identity hash in `configuration` or `bouncer`.
- Copying AppSec timeout or TLS from LAPI.
- Moving `defaultDecisionSeconds` off `Bouncer` / `LiveLookup`.
- Shipping `docs/config-domain-prefixes.md`.
- Migrating `openspec/changes/archive` or other runs' `devstate`.
- Writing `knowledge/devdocs` packets in this phase (Language deltas already shown; implement / `opd-devdocsimpact` fold them).
- Renaming CrowdSec protocol constants (`X-Api-Key`, `v1/decisions`, CAPI `machine_id`).

## Decisions

| Topic | Choice | Rationale |
|-------|--------|-----------|
| Public surface | Flat JSON tags + matching Go fields; prefix stays on `configuration.Config` only | Operator label. Explore seam. No aliases. |
| Package boundary | Prefix drops at `pkg/lapi` / `pkg/appsec` / captcha args | Name for the scope. AppSec already dropped. LAPI matches. |
| TLS client cert | `lapiTlsClientCertificate` / `appsecTlsClientCertificate`; inside packages `TLSClientCertificate` | Old `CertificateBouncer` collided with the bouncer prefix. |
| Timeouts | Three knobs default 10, `requiredInt1`; delete `HTTPTimeoutSeconds` and `EffectiveHTTPTimeoutSeconds` | Nothing inherits. AppSec scheme/key copy stays; timeout does not. |
| Ownership timeout | `LapiHTTPTimeoutSeconds` / `AppsecHTTPTimeoutSeconds` on that leg's ownership key | Timeout change Opens a new Client. Connection spec Adopt-on-timeout is replaced. SessionHex still omits timeout. |
| Identity JSON | Reuse `identity.go` (`identity` + `ownership`) and `session.go` | One job, one owner. Drop redundant `lapi` prefix and `tlsCertificateBouncer` on those marshalers. Hash change = process restart. |
| Bouncer locals | Keep `lapiFailureAction` / `appsecFailureAction`; rename `streamStartupBlock` → `startupBlock` | Distinguishing names stay. Flag gates every subscribed leg. |
| Captcha | Pass `BouncerCaptcha*` into existing `siteKey` / `secretKey` / `gateSecret` args | Do not grow a `bouncer` field on `pkg/captcha`. |
| Catalog | Fold the eleven explore leaves; no new family | Live promises already live there. |
| GetVariable | Strings are new Go field names; helpers `Lapi`/`Appsec` + `TLSCertificateAuthority` / `TLSClientCertificate` / `TLSClientKey` | Reflect `FieldByName`. |

**Alternatives rejected:** old-key aliases; nested YAML; reconstructing reclaim JSON in `configuration` or `bouncer`; a new spec family; committing `docs/config-domain-prefixes.md`.

## Risks / Trade-offs

- **Every in-tree operator file breaks until renamed** → Implement walks the explore inventory (34 GetVariable sites, 11 examples, 12 mock dynamics, 2 real e2e, README, `.traefik.yml`). No alias.
- **Reclaim hash changes** → Same break as the public rename. Process restart. Do not measure or support in-process reclaim without restart.
- **LAPI connection spec previously Adopted on timeout** → Ownership key already includes timeout (reclaim-key). This change makes connection match: timeout change Opens a new Client.
- **Stale usage packets** → Enough to call the subsystems. Implement / `opd-devdocsimpact` fold them. Not a hard produce gap.

## Migration Plan

- Operators rewrite plugin YAML/labels to the new keys. No compatibility window.
- Shared `httpTimeoutSeconds: N` becomes `lapiHttpTimeoutSeconds: N` and `appsecHttpTimeoutSeconds: N` (captcha siteverify is its own knob, default 10).
- `crowdsecMode: appsec` stays invalid; AppSec-only is `lapiEnabled: false` plus `appsecEnabled: true`.
- README, examples, and e2e ship the new names in the same change.
- Rollback is revert of the PR; old keys do not work on the new binary.

## Open Questions

None. Explore rows stay as explore wrote them.
