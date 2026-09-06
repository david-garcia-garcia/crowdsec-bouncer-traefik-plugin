## ADDED Requirements

### Requirement: One in-flight stream poll per Client
A stream or alone `lapi.Client` SHALL run at most one `GET /v1/decisions/stream` at a time. When a ticker tick or `Wake` would start a second poll while one is in flight, that extra work SHALL be skipped. A skip SHALL NOT reset the stream failure counter and SHALL NOT mark the stream healthy. The stream ticker goroutine MUST NOT wait for a poll to finish (metrics MUST keep firing while a poll is in flight or hung until timeout). The Redis/memory lease key `updated` SHALL still skip a poll when a sibling instance already leased this interval; that sibling skip remains a successful poll.

#### Scenario: Overlapping Wake and ticker skip
- **WHEN** a stream poll is in flight
- **AND** the ticker fires or `Wake` starts another poll on the same Client
- **THEN** only one stream GET is in flight
- **AND** the extra work does not clear `updateFailure` or force the stream healthy

#### Scenario: Ticker keeps firing during a slow poll
- **WHEN** a stream GET is held until `HTTPTimeoutSeconds`
- **THEN** the metrics ticker can still run
- **AND** the stream ticker does not stop for the duration of that GET
