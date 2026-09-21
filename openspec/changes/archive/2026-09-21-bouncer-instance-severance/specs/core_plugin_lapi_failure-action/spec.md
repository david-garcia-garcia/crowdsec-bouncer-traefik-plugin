## ADDED Requirements

### Requirement: Missing named LAPI client uses LAPI failure action
When `lapiEnabled` is true and Peek of the named LAPI slot misses, the bouncing handler SHALL apply `bouncerLapiFailureAction` the same way a live LAPI error does.

#### Scenario: Subscribe miss bans by default
- **WHEN** a bouncing router has `lapiEnabled` true, `lapiInstance` `shared`, empty LAPI failure action, and no Client is published
- **THEN** the request is remediated as a ban
