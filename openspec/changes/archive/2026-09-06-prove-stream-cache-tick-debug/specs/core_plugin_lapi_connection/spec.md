## ADDED Requirements

### Requirement: Stream poll ticks stay at DEBUG

Successful stream cache ticks SHALL emit `handleStreamCache:updated` after a LAPI fetch and `handleStreamCache:alreadyUpdated` when the stream lease is already held. Both messages MUST be DEBUG. They MUST NOT appear when the plugin logger is at the default INFO level. Stream health transitions (`crowdsec stream became healthy` / `crowdsec stream became unhealthy`) remain INFO and are not this requirement.

#### Scenario: Lease miss does not INFO-spam

- **WHEN** stream mode polls LAPI because the stream lease is missing and the fetch succeeds
- **THEN** `handleStreamCache:updated` is present at DEBUG
- **AND** that message is absent when the logger is at INFO

#### Scenario: Lease hit does not INFO-spam

- **WHEN** stream mode ticks while the stream lease is already held
- **THEN** `handleStreamCache:alreadyUpdated` is present at DEBUG
- **AND** that message is absent when the logger is at INFO
