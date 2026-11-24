## ADDED Requirements

### Requirement: Gate skip answers with the ModSec backoff action
When the Client holds a Gate, `Inspect` SHALL `Admit` after the body is read and checked against the limit, and before the sidecar hop. A denied admission SHALL return `ErrGateSkip` without a Report and without a sidecar call. An unreadable body that would be `ErrUnavailable` SHALL also be `ErrGateSkip` while the Gate is backing off. A usable inspect (2xx or copied 3xx/4xx) SHALL Report success; a transport error or sidecar 5xx SHALL Report failure.

#### Scenario: After the trip the default skip continues
- **WHEN** `bouncerModsecFailureAction` is `ban` and the sidecar fails 5 times in a row
- **AND** `bouncerModsecBackOffAction` is omitted
- **THEN** those 5 requests answer `ban:modsec-failure`
- **AND** the next request does not call the sidecar and reaches `next` with no remediation header

#### Scenario: Body limit still applies after the trip
- **WHEN** the Gate is skipping
- **AND** a POST body exceeds `modsecBodyLimit`
- **THEN** the response is HTTP 413

#### Scenario: Unreadable body while backing off is a skip
- **WHEN** the Gate is backing off and `bouncerModsecFailureAction` is `ban`
- **AND** a POST body arrives with no length
- **THEN** `Inspect` returns `ErrGateSkip` without calling the sidecar

### Requirement: ModSec gate skip uses bouncerModsecBackOffAction
On `ErrGateSkip` the router SHALL apply its own `bouncerModsecBackOffAction` and MUST NOT apply `bouncerModsecFailureAction`. `passthrough` (default; empty means `passthrough`) SHALL call `next`. `ban` SHALL write the ban template with RemediationReason `MODSEC` and header `ban:modsec-backoff`. `captcha` SHALL serve this router's captcha gate with `captcha:modsec-backoff`. Both SHALL count under origin `plugin:modsec_failure`.

#### Scenario: Backoff action ban
- **WHEN** the ModSec Gate denies admission and `bouncerModsecBackOffAction` is `ban`
- **THEN** the response is the ban template with reason `MODSEC` and `ban:modsec-backoff`
- **AND** the sidecar is not called
- **AND** `next` is not called

#### Scenario: Backoff action captcha
- **WHEN** the ModSec Gate denies admission, `bouncerModsecBackOffAction` is `captcha`, and the router has a usable captcha client
- **THEN** the router's captcha page is served with `captcha:modsec-backoff`

#### Scenario: Failure action does not decide a skip
- **WHEN** the ModSec Gate denies admission, `bouncerModsecFailureAction` is `ban`, and `bouncerModsecBackOffAction` is `passthrough`
- **THEN** the request reaches `next` with no remediation header

## REMOVED Requirements

### Requirement: Gate skip continues without the sidecar and without the failure action
**Reason**: A gate skip no longer always continues: it answers with the per-router `bouncerModsecBackOffAction`.
**Migration**: "Gate skip answers with the ModSec backoff action" keeps the admission order, the Report rules, and the 413 case. "ModSec gate skip uses bouncerModsecBackOffAction" sets the answer. The default `passthrough` keeps the old behaviour.
