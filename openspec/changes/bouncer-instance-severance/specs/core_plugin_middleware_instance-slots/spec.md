## ADDED Requirements

### Requirement: Named LAPI and AppSec slots are separate tables
The plugin SHALL maintain two process-wide slot tables: one for the LAPI leg and one for the AppSec leg. A slot is keyed by leg plus instance name string. The same instance name MAY exist in both tables at once. Each slot SHALL record the Traefik middleware name that published it, the current `*lapi.Client` or `*appsec.Client` pointer (or empty), and a subscriber list of `*atomic.Value` targets. Implementations MUST NOT use `atomic.Pointer[T]` or function callbacks for fan-out (Yaegi constraint).

#### Scenario: LAPI shared and AppSec shared are independent
- **WHEN** one middleware publishes LAPI instance `shared` and AppSec instance `shared`
- **THEN** both slots exist in their respective tables with the same string name
- **AND** unpublish or Clear on one leg does not clear the other leg's slot

### Requirement: Publish stores the client and fans out synchronously
When an owning middleware successfully Opens a client for a leg it SHALL Publish that instance name under the slot mutex: set `current` to the client pointer, record this middleware as publisher, and `Store` the same pointer into every registered subscriber `atomic.Value` before releasing the mutex. Publish SHALL NOT run on the request path. A publish that replaces `current` with a different client pointer SHALL emit bouncer bound logs for each subscriber that receives the new pointer.

#### Scenario: Subscriber receives client on owner's Publish
- **WHEN** a bouncer subscribed to LAPI name `shared` before the owner Publish
- **AND** the owner Publish runs with a non-nil LAPI client
- **THEN** the bouncer's LAPI `atomic.Value` holds that client before the owner's `New` returns
- **AND** no goroutine was started solely to notify subscribers

### Requirement: Subscribe registers without waiting
Subscribe SHALL append the bouncer's `*atomic.Value` to the named slot under the mutex, copy `current` into that value (typed nil when empty), and return immediately. Subscribe MUST NOT block until a publisher exists. Unsubscribe SHALL run when the bouncer's constructor context is Done and SHALL remove that `atomic.Value` from the list without closing the backend client.

#### Scenario: Subscribe before Publish leaves typed nil until Publish
- **WHEN** a bouncer Subscribe runs for a name with no publisher yet
- **THEN** `New` returns successfully
- **AND** the bound field holds a typed nil until a later Publish Stores a client

### Requirement: Clear is generation-aware on grace Close
When a client incarnation grace `Close` runs, Clear SHALL iterate slots in that leg's table where `current` is still that dying pointer and the recorded publisher matches that client's middleware. For each such slot, Clear SHALL store a typed nil into every subscriber and clear `current`. When `current` already points at a replacement client, Clear for the dying pointer SHALL be a no-op on that slot.

#### Scenario: Replacement publish before old Close does not unbind new client
- **WHEN** slot `shared` published client B while client A is in grace
- **AND** A's Close runs Clear for A
- **THEN** subscribers still hold B
- **AND** Clear does not Store nil over B

### Requirement: Exclusive publish rejects a second publisher
Publish onto a name already held by a different middleware in the same table SHALL NOT change `current` or the recorded publisher. The attempting `New` SHALL unpublish every slot that attempt already wrote in that constructor, cancel its holder child context, return an error, and log one ERROR `crowdsec instance name taken` naming leg, instance name, existing publisher, and rejected middleware (no API key). Multi-leg publish attempts SHALL roll back all legs written in that attempt before releasing the mutex.

#### Scenario: Second opener on same LAPI name fails New
- **WHEN** middleware `cs-a` already published LAPI `shared`
- **AND** middleware `cs-b` attempts to publish LAPI `shared` in the same process
- **THEN** `cs-b` `New` fails
- **AND** subscribers remain bound to `cs-a`'s client

### Requirement: Client remembers last published slot for rename Wake
An owning LAPI or AppSec Client SHALL store the instance name it last published. On Wake when the configured instance name differs, the Client SHALL unpublish the stored name (only if it is still publisher and `current` is this Client) before publishing the new name. Sleep SHALL leave the stored name for the following Wake.

#### Scenario: Same Client new slot name unbinds old subscribers first
- **WHEN** a Woken Client republishes under a new instance name without a new reclaim key
- **THEN** subscribers of the old name receive unbound then subscribers of the new name receive bound
- **AND** no second `instance started` log for the same incarnation

### Requirement: Lifecycle logs match e2e grep contract
Backend Create/Close at INFO, Sleep/Wake at DEBUG, with stable `msg` values `crowdsec lapi instance …` / `crowdsec appsec instance …`, attrs `leg`, `instanceName`, `incarnation`. Bouncer bound/unbound at INFO with `msg` `crowdsec bouncer bound` / `crowdsec bouncer unbound`, attrs `traefikName`, `leg`, `instanceName`, `incarnation`. These lines MUST NOT be emitted on the request path.

#### Scenario: Replace A by B logs two bound lines
- **WHEN** Publish replaces client A with B on the same slot for a subscriber
- **THEN** logs show bound for A then bound for B without an unbound between them on that subscriber
