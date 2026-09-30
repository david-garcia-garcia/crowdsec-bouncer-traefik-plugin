## ADDED Requirements

### Requirement: AppSec URI is the inbound-request absolute URL
`Query` SHALL take the inbound request value instead of a parallel IP string plus a bare `*http.Request`. `Query` SHALL set `X-Crowdsec-Appsec-Uri` to that value's absolute client-facing URL. `Query` MUST NOT set that header from `URL.String()` or `URL.Scheme`. `Query` MUST NOT derive scheme from `X-Forwarded-Proto` or `Request.TLS`. `X-Crowdsec-Appsec-Host` SHALL remain `Request.Host`.

#### Scenario: Absolute URI uses constructor scheme
- **WHEN** the inbound-request scheme is `https`
- **AND** `URL.String()` is path-only
- **THEN** `X-Crowdsec-Appsec-Uri` is an absolute URL whose scheme is `https`

#### Scenario: Host header stays Request.Host
- **WHEN** `Query` forwards a request
- **THEN** `X-Crowdsec-Appsec-Host` equals `Request.Host`

## MODIFIED Requirements

### Requirement: Outbound Content-Length matches forwarded bytes
After `Query` chooses the bytes sent to AppSec, it SHALL omit the client's `Content-Length` and `Transfer-Encoding` from the copied headers and SHALL set the AppSec request `ContentLength` field and `Content-Length` header from those bytes. It SHALL set that header only on the outbound POST that carries those bytes; a bodyless GET to AppSec SHALL carry no `Content-Length`. `Query` SHALL reuse the inbound request value's remoteIP already chosen by `pkg/ip.GetRemoteIP`; it MUST NOT reconstruct the client address.

#### Scenario: Forwarded body length wins
- **WHEN** the client `Content-Length` disagrees with the bytes `Query` forwards
- **THEN** the AppSec request `ContentLength` field and `Content-Length` header equal the forwarded length

#### Scenario: Bodyless forward carries no length header
- **WHEN** `Query` forwards a request to AppSec as a bodyless GET
- **THEN** the AppSec request has no `Content-Length` header
