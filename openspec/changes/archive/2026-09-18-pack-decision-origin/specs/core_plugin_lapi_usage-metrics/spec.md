## ADDED Requirements

### Requirement: Active-decision slots store origin id and family
In stream and alone modes, `activeDecisionSlots` SHALL remain a per-slot map so forget can drop one record. Each interned slot value SHALL store the DecisionStore origin id and the decision-value family (`4` / `6` from `FamilyOfHostOrCIDR`) instead of a five-string `usageMetricKey`. The POST `origin` and `ip_type` labels SHALL still be the `MetricsOrigin` string and `ipv4` / `ipv6`. The reporter SHALL resolve names through the shared DecisionStore table (MUST NOT keep a second intern table). A slot that could not intern (overflow or empty origin) SHALL keep enough to POST the same labels as today. The plugin MUST NOT delete `activeDecisionSlots`.

#### Scenario: Stream IP ban still counts with packed slots
- **WHEN** stream applies one Ip ban whose value is `1.2.3.4` and origin is `crowdsec`
- **THEN** `active_decisions` includes 1 with `origin=crowdsec` and `ip_type=ipv4`
- **AND** the slot value does not store the five-string `usageMetricKey`

#### Scenario: Forget still needs the slot
- **WHEN** stream deletes that Ip ban
- **THEN** `active_decisions` no longer includes that record
