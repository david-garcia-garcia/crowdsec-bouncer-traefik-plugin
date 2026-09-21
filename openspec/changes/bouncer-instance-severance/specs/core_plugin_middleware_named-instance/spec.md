## ADDED Requirements

### Requirement: Named LAPI and AppSec slots
The process SHALL keep one named slot per operator LAPI instance name and one per AppSec instance name. After a successful identity `Open`, `New` SHALL publish that `*Client` into the slot for the instance name (empty config name means Traefik `New` name). A bouncing handler SHALL Peek the slot on each request and MUST NOT store the `*Client` from construct. Implementations MUST use `atomic.Value` for the slot (not `atomic.Pointer[T]`). Subscribers MUST NOT bind the identity reclaim table. A second Open of the same name with a different LAPI or AppSec identity SHALL fail `New`. Peek miss is owned by the failure-action leaves.

#### Scenario: Subscriber New succeeds before the opener
- **WHEN** a bouncing `New` names `lapiInstance: shared` with no LAPI secrets and no opener has published `shared`
- **THEN** `New` returns a handler
- **AND** that handler has not opened a LAPI Client

#### Scenario: Request sees the client after a later Open
- **WHEN** the opener for `shared` then publishes a LAPI Client
- **AND** a later request hits the subscriber
- **THEN** that request uses the published Client

#### Scenario: Same name different host fails
- **WHEN** an opener already published `shared` for LAPI host A
- **AND** a later `New` Opens LAPI host B with `lapiInstance: shared`
- **THEN** the second `New` returns an error
