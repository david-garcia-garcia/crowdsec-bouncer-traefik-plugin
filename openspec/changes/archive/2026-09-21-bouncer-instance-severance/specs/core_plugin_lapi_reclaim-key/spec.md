## MODIFIED Requirements

### Requirement: Stream session is LAPI URL plus bouncer key
(Unchanged Open-key composition.) Exclusive ownership of the DecisionStore SHALL use the LAPI instance name (`lapiInstance`, or Traefik `New` name when that field is empty), not a bouncing subscriber's Traefik name. Same instance name on many Openers MUST share. A different instance name on the same SessionHex SHALL fail `New` before Open.

#### Scenario: Same LAPI key two instance names fail the second New
- **WHEN** two Open `New` calls use stream mode, the same LAPI URL and key, and different `lapiInstance` values, each with a live constructor context
- **THEN** the first constructor receives a DecisionStore and Client
- **AND** the second constructor returns an error and does not Open or Wake that store

#### Scenario: Same instance name many Openers share one stream
- **WHEN** two Open `New` calls use stream mode, the same LAPI URL and key, and the same `lapiInstance`, each with a live constructor context
- **THEN** both receive the same LAPI connection incarnation
- **AND** only one stream ticker is running for that session
