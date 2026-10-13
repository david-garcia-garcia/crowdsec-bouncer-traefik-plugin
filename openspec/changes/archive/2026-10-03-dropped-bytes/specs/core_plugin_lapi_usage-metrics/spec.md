## ADDED Requirements

### Requirement: Dropped items also send a byte series
Each remediating drop SHALL increment a `dropped` item with unit `byte` in the same usage-metrics window as the `dropped` item with unit `request`. The request series SHALL remain. Labels on the byte item SHALL include `origin` and `ip_type` with the same values as that paired request item, and MUST NOT include `remediation`. The byte value SHALL be the inbound request's size estimate owned by that request cluster: `len` of `RequestURI`, `len` of the server-lifted `Host` field, `len` of each Header map key once plus `len` of each header value, plus the declared `ContentLength` when it is `>= 0`. When `ContentLength` is greater than 50 mebibytes (`50 * 1024 * 1024`), that part SHALL count 50 mebibytes. When `ContentLength` is `-1`, that part SHALL add nothing. The estimate MUST NOT read `Body`. The estimate MUST NOT reconstruct a wire image (`httputil.DumpRequest`, `Request.Write`, method, version, CRLF, or colon-space). Host SHALL be the lifted `Host` field only; the path MUST NOT parse `:authority`, `X-Forwarded-Host`, or `Header["Host"]`.

#### Scenario: Ban drop posts both series
- **WHEN** a request is banned
- **THEN** the next usage-metrics POST includes a `dropped` item with unit `request` and a `dropped` item with unit `byte`
- **AND** both items share that drop's `origin` and `ip_type`
- **AND** the byte item has no `remediation` label

#### Scenario: Byte value uses named fields
- **WHEN** a remediating drop has `RequestURI` `/a`, Host `h`, one Header entry `X-A` with value `b`, and `ContentLength` 10
- **THEN** the `dropped` / `byte` item value is `len("/a") + len("h") + len("X-A") + len("b") + 10`

#### Scenario: ContentLength above the cap
- **WHEN** a remediating drop reports `ContentLength` greater than `50 * 1024 * 1024`
- **THEN** the ContentLength part of the `dropped` / `byte` value is `50 * 1024 * 1024`

#### Scenario: Unknown body length adds nothing
- **WHEN** a remediating drop has `ContentLength` `-1`
- **THEN** the `dropped` / `byte` value does not include a body contribution
- **AND** the path does not read `Body`

### Requirement: Byte window counters saturate
The running `dropped` / `byte` counters in the usage-metrics window (the values summed until the next successful POST, including a failed POST that restores those keys) SHALL saturate at the maximum of the counter type instead of wrapping. A single request's capped estimate MUST fit that type.

#### Scenario: Add that would overflow stays at maximum
- **WHEN** adding a byte delta would exceed the counter maximum
- **THEN** the stored `dropped` / `byte` window value is that maximum

#### Scenario: Failed POST restore saturates
- **WHEN** a failed POST restores `dropped` / `byte` window keys whose sum would overflow
- **THEN** those keys stay at the counter maximum
