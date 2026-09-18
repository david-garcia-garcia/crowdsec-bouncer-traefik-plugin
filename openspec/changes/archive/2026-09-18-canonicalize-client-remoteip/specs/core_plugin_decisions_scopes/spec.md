## MODIFIED Requirements

### Requirement: Ip decisions key on the canonical address
An `Ip` decision SHALL be cached and looked up under one canonical spelling of the address. The store path SHALL key a decision value that is a `/32` or `/128` CIDR on the host address; a value that parses as a bare address SHALL key on `net.IP.String()` of that address, which collapses expanded, upper-case, and IPv4-mapped spellings; a value that parses as neither SHALL be keyed verbatim. After `GetRemoteIP` yields a parsed address, `clientRequest.remoteIP` SHALL be that address's `net.IP.String()` and the request path SHALL look up the Ip slot under that string. It MUST NOT re-parse the client address and MUST NOT use a second request-path key helper. Until that parse succeeds, `remoteIP` SHALL stay the raw extracted text so extract-fail and unparseable-address remediations can log it. Live-mode memo SHALL write under that same canonical `remoteIP` and MUST NOT re-derive a key from the raw header. Captcha gate bind SHALL compare that same canonical `remoteIP`. The store side and the request side MUST NOT be changed independently: a canonical read against a verbatim write is a permanent cache miss. Non-IP scopes MUST NOT be pushed through address parsing.

#### Scenario: Bare IP ban still works
- **WHEN** an Ip ban exists for the client IP
- **THEN** the request is forbidden

#### Scenario: Expanded IPv6 decision matches a compressed request
- **WHEN** the stream stored an Ip ban whose value is `2001:0db8:0000:0000:0000:0000:0000:0001` and the request address is `2001:db8::1`
- **THEN** the request is forbidden

#### Scenario: Upper-case IPv6 decision matches a lower-case request
- **WHEN** the stream stored an Ip ban whose value is `2001:DB8::1` and the request address is `2001:db8::1`
- **THEN** the request is forbidden

#### Scenario: IPv4-mapped and dotted forms share one slot
- **WHEN** the stream stored an Ip ban whose value is `::ffff:192.0.2.4` and the request address is `192.0.2.4`, or the reverse
- **THEN** the request is forbidden

#### Scenario: Live-mode memo still hits on a repeated request
- **WHEN** live mode answers a request from an address spelled `2001:DB8::1` and four more requests arrive from that same address inside the live-cache TTL
- **THEN** LAPI is queried once, not once per request

#### Scenario: Country value is not an address
- **WHEN** a Country decision carries the value `fr`
- **THEN** it is keyed as the normalized header scope `country:FR` and is not parsed as an address

#### Scenario: Real CrowdSec Ip ban matches a different request spelling in none mode
- **WHEN** a live LAPI holds an Ip ban whose value is an expanded IPv6, an upper-case IPv6, or an IPv4-mapped address, and Traefik is hit in none mode with a different spelling of that same address on the forwarded header
- **THEN** the request is forbidden

#### Scenario: Real CrowdSec Ip ban matches a different request spelling in stream mode
- **WHEN** a live LAPI holds an Ip ban whose value is an expanded IPv6, an upper-case IPv6, or an IPv4-mapped address, and Traefik is hit in stream mode with a different spelling of that same address on the forwarded header
- **THEN** the request is forbidden after the stream poll applies the decision

#### Scenario: Captcha gate bind uses the canonical remoteIP
- **WHEN** captcha grace is bound to the client address and a later request arrives with a different spelling of the same address
- **THEN** the gate cookie still matches

#### Scenario: Unparseable address keeps the raw remoteIP
- **WHEN** `GetRemoteIP` returns raw header text and a nil parsed address
- **THEN** the request is remediating as an unparseable-address failure and the raw text is what the failure log shows
