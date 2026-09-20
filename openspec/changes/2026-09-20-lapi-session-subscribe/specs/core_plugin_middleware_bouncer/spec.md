## MODIFIED Requirements

### Requirement: A failed New releases the holders it already opened
`New` SHALL bind every reclaim `Open` it makes (LAPI client, AppSec client) to one context derived from the constructor context, and SHALL release that context on every path where it returns an error. `New` MUST NOT Open a DecisionStore as a separate reclaim holder; the LAPI Client `create()` owns that store and the Client Close hook Closes it. A constructor that fails after an earlier `Open` succeeded MUST NOT leave that incarnation held: with zero table grace its `Close` hook SHALL run, that Close SHALL Close the child DecisionStore, and a stream ticker it started MUST NOT keep polling LAPI. The derived context SHALL stay a child of the constructor context, so cancelling Traefik's context still releases the holders of a `New` that succeeded. The success path MUST NOT release it.

#### Scenario: AppSec Open fails after a stream client was opened
- **WHEN** `crowdsecMode` is `stream`, the LAPI stream client opens, and `appsec.Open` then fails
- **THEN** `New` returns that error
- **AND** the LAPI incarnation is no longer held
- **AND** its stream ticker stops polling LAPI
- **AND** its child DecisionStore is Closed

#### Scenario: A successful New keeps its holder
- **WHEN** `New` returns a handler
- **THEN** the incarnations it opened are still held
- **AND** cancelling the constructor context releases them
