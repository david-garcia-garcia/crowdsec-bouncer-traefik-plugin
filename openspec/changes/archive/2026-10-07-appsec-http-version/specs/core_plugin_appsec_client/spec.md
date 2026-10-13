## ADDED Requirements

### Requirement: Query forwards client HTTP version
`Query` SHALL set `X-Crowdsec-Appsec-Http-Version` on the outbound AppSec request to two ASCII digits, major then minor, from the inbound request `ProtoMajor` and `ProtoMinor`. HTTP/1.0 SHALL be `10`, HTTP/1.1 SHALL be `11`, HTTP/2 SHALL be `20`, HTTP/3 SHALL be `30`. `Query` SHALL omit that header when `ProtoMajor` is 0. `Query` MUST NOT parse `Request.Proto` to invent the digits. `Query` MUST NOT snapshot HTTP version on the inbound-request constructor. Other `X-Crowdsec-Appsec-*` headers SHALL remain unchanged.

#### Scenario: HTTP/1.1 encodes as 11
- **WHEN** `Query` forwards a request whose `ProtoMajor` is 1 and `ProtoMinor` is 1
- **THEN** `X-Crowdsec-Appsec-Http-Version` is `11`

#### Scenario: HTTP/2 encodes as 20
- **WHEN** `Query` forwards a request whose `ProtoMajor` is 2 and `ProtoMinor` is 0
- **THEN** `X-Crowdsec-Appsec-Http-Version` is `20`

#### Scenario: HTTP/3 encodes as 30
- **WHEN** `Query` forwards a request whose `ProtoMajor` is 3 and `ProtoMinor` is 0
- **THEN** `X-Crowdsec-Appsec-Http-Version` is `30`

#### Scenario: ProtoMajor 0 omits the header
- **WHEN** `Query` forwards a request whose `ProtoMajor` is 0
- **THEN** `X-Crowdsec-Appsec-Http-Version` is absent
