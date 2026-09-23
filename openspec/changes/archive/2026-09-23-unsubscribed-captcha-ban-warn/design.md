## Context

See proposal.md Why. Dest already bans captcha kind when the loaded client is nil or `!Valid` (`handleRemediationServeHTTP`). Startup-block 503 plus WARN `crowdsec bouncer backend missing` runs only when this router subscribed and the client is still nil. Explore Decisions are accepted: one WARN in `handleRemediationServeHTTP` gated on captcha kind and `!subscribeCaptcha`; stem `crowdsec bouncer captcha unsubscribed`; attrs `leg=captcha` and `instanceName`; every remediating request; all captcha-kind remediations that reach that handler; do not emit `ip`; do not WARN subscribed-unpublished. Identity owner is `pkg/ip.GetRemoteIP` on `clientRequest.remoteIP`.

## Goals / Non-Goals

**Goals:**

- One WARN on the existing captcha-kind degrade, then the existing ban.
- Same attr pair as `warnBackendMissing` (`leg`, `instanceName`).
- Tests through `newTestLogSink` (`std_go_test_log-sink`).

**Non-Goals:**

- A `sync.Once` / per-binding counter.
- New public config keys, or legalizing failure-action `captcha` without an instance name.
- WARN on subscribed-unpublished or `!Valid`.
- Reconstructing `RemoteAddr` or Host, or emitting `ip` on this WARN.
- Serving a challenge without a published client.
- AppSec JSON `action: captcha` (`handleAppsecResponseServeHTTP`).
- Writing `knowledge/devdocs` this phase.

## Decisions

| Topic | Choice | Rationale |
|-------|--------|-----------|
| Seam | `handleRemediationServeHTTP` when kind is captcha and `!b.subscribeCaptcha`, then existing ban | One owner for captcha-kind serve vs ban. All three signals already reach here. |
| Gate | `subscribeCaptcha` false only | Out of scope to WARN subscribed-unpublished. Startup-block sibling stays `warnBackendMissing`. |
| Stem / attrs | `crowdsec bouncer captcha unsubscribed`; `leg=captcha`; `instanceName` from `captchaInstanceName` (empty when unsubscribed) | Matches `warnBackendMissing` attr names. `traefikName` already on the logger from `bouncer.New`. |
| Cadence | Every remediating request | Matches `warnBackendMissing` and `ServeHTTP:forcedCaptchaSuperseded`. No `Once` field. |
| Identity | Do not emit `ip`. Do not call `GetRemoteIP` again | Owner is `pkg/ip.GetRemoteIP` on `clientRequest`. This WARN is router subscription. |
| Catalog | Fold `core_plugin_middleware_bouncer` only | Small adjustment to the unpublished-client ban leaf. Neighbors stay as-is. |

**Alternatives rejected:** WARN on every nil/`!Valid` client; a `Once` field; new public knobs; reconstructing a local captcha client on bounce-only; WARN on AppSec JSON `action: captcha`; a new spec family.

## Risks / Trade-offs

- **WARN volume on every remediating request** → Accepted. Siblings already warn per request. Do not add a counter.
- **Failure-action `captcha` without an instance name never reaches this path** → `ValidateParams` already rejects it. Keep that gate. Tests still cover LAPI captcha kind and forced `c`.
- **Operator sees ban plus WARN, not a new status code** → Desired. Do not change the 403.

## Migration Plan

- Deploy. No config rewrite. Rollback is revert of the PR.

## Open Questions

None. Explore rows stay as explore wrote them.
