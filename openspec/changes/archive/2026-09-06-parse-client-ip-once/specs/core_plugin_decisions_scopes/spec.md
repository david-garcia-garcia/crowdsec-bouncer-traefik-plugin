## MODIFIED Requirements

### Requirement: Client IP comes from GetRemoteIP
The bouncer SHALL identify the client IP using the existing remote-IP owner (`pkg/ip.GetRemoteIP`). It MUST NOT parse `RemoteAddr` a second time for decision matching. Stream/alone Range membership SHALL classify the `net.IP` GetRemoteIP already yielded. Range lookup MUST NOT parse the client string.

#### Scenario: Forwarded IP is the lookup address
- **WHEN** Traefik forwards a trusted `X-Forwarded-For` for a banned IP
- **THEN** Ip-scope matching uses that address

#### Scenario: Range membership uses the parsed client IP
- **WHEN** stream has a Range ban `10.0.0.0/8` and GetRemoteIP yielded `10.1.2.3` as `net.IP`
- **THEN** Range matching uses that `net.IP` and MUST NOT parse the client string again
