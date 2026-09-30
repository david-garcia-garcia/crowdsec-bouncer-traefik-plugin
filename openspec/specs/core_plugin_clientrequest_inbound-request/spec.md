## Purpose

Holds one inbound HTTP request together with the client address GetRemoteIP already chose and the client-facing scheme token the constructor derived, so captcha gate Secure and AppSec `X-Crowdsec-Appsec-Uri` share that scheme.

## Requirements

### Requirement: Inbound request cluster lives in package clientrequest
The plugin SHALL own one inbound request plus the client address `pkg/ip.GetRemoteIP` already chose plus the scheme token in `package clientrequest`. The exported type SHALL be `Request`. Callers SHALL keep the parameter name `req`. The package MUST NOT import `pkg/bouncer`, `pkg/captcha`, or `pkg/appsec`. Scopes, remediation origin, and captcha state MUST NOT live on this type. The type MUST NOT parse `RemoteAddr` or walk forwarded hops. The parsed address, its family (`ip.FamilyOfIP` of that address), and the remote-IP string SHALL be constructor snapshots exposed by getters. Callers MUST NOT assign them after construction. When the parsed address is non-nil, the stored remote-IP string SHALL be `ipAddr.String()`. When it is nil, the stored string SHALL stay the raw extract `GetRemoteIP` returned.

#### Scenario: Bouncer constructs after GetRemoteIP
- **WHEN** `ServeHTTP` has a client address from `GetRemoteIP`
- **THEN** it builds one `clientrequest.Request` from that address and the live `*http.Request`
- **AND** captcha and AppSec receive that value instead of a bare `*http.Request` plus a parallel IP string

### Requirement: Constructor owns the scheme token
When the constructor builds `Request`, it SHALL set scheme as follows. If `X-Forwarded-Proto`, trimmed, matches the whole value `http` or `https` case-insensitively, that token (as `http` or `https`) is the scheme. No comma split. Otherwise scheme SHALL be `https` when `Request.TLS` is non-nil, else `http`. The constructor MUST NOT treat `wss`, empty, `https,http`, `Forwarded`, `Front-End-Https`, `X-Forwarded-Protocol`, `X-Scheme`, or `URL.Scheme` as a set proto. Callers MUST NOT assign scheme after construction. The constructor MUST NOT re-check `forwardedHeadersTrustedIps` or `ForwardedHeadersInsecure`.

#### Scenario: Forwarded https without TLS is https
- **WHEN** `X-Forwarded-Proto` is `https` (any case, optional surrounding space)
- **AND** `Request.TLS` is nil
- **THEN** scheme is `https`

#### Scenario: Explicit proto http with TLS is http
- **WHEN** `X-Forwarded-Proto` is `http` (any case, optional surrounding space)
- **AND** `Request.TLS` is set
- **THEN** scheme is `http`

#### Scenario: TLS fallback when proto is not a set token
- **WHEN** `X-Forwarded-Proto` is `wss`, empty, `https,http`, or absent
- **AND** `Request.TLS` is set
- **THEN** scheme is `https`

#### Scenario: HTTP fallback when proto is not a set token and TLS is nil
- **WHEN** `X-Forwarded-Proto` is `wss`, empty, `https,http`, or absent
- **AND** `Request.TLS` is nil
- **THEN** scheme is `http`

#### Scenario: URL.Scheme is not a set proto
- **WHEN** `URL.Scheme` is `https`
- **AND** `X-Forwarded-Proto` is absent
- **AND** `Request.TLS` is nil
- **THEN** scheme is `http`

### Requirement: Live request is not rewritten
The constructor MUST NOT write scheme onto the live `*http.Request` that Traefik and next still hold.

#### Scenario: URL.Scheme stays as Traefik left it
- **WHEN** the constructor runs on a request whose `URL.Scheme` is empty
- **THEN** that `URL.Scheme` is still empty afterwards

### Requirement: Absolute client-facing URL uses constructor scheme
`Request` SHALL expose the absolute client-facing URL whose scheme is the constructor token, whose host is `URL.Host` when that is non-empty otherwise `Request.Host`, and whose path and query are preserved from `URL`. It MUST NOT use `URL.Scheme`.

#### Scenario: Origin-form Traefik request becomes an absolute URL
- **WHEN** scheme is `https`
- **AND** `URL.Host` is empty
- **AND** `Request.Host` is `app.example`
- **AND** the path is `/foo` with query `q=1`
- **THEN** the absolute URL is `https://app.example/foo?q=1`

#### Scenario: URL.Host wins when set
- **WHEN** `URL.Host` is `url.example`
- **AND** `Request.Host` is `req.example`
- **THEN** the absolute URL host is `url.example`
