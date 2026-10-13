# AppSec TLS does not follow an inherited LAPI scheme

IssueKey: 2026-09-22-bouncer-instance-severance
Size: large
Action: note

## Why this follow-up

When AppSec is enabled, `Prepare` copies an empty `crowdsecAppsecKey` from `crowdsecLapiKey` and an empty `crowdsecAppsecScheme` from `crowdsecLapiScheme`. AppSec TLS material (CA, client certificate, insecure-verify) is not copied. An inherited `https` scheme still uses an empty AppSec CA, so verification can fail while LAPI succeeds. Assumed OK for this change. Later: copy LAPI CA, client certificate, and insecure-verify when no AppSec TLS material is set.

## Why it was not taken

The ticket scoped AppSec ownership keys and scheme/key copy only. TLS follow-through is a second secret-resolution path with its own fail-closed cases.

## Risks

AppSec-on-https with an omitted AppSec CA fails Open (or TLS verify) while LAPI with the same operator intent succeeds. Operators must set AppSec TLS knobs explicitly when they inherit `https`.
