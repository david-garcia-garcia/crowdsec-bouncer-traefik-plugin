## ADDED Requirements

### Requirement: Active-decision slots store intern id and family
In stream and alone modes, the per-slot forget map SHALL keep one entry per active Ip, header-scope, or Range record. Each slot SHALL store the intern `originID` and the `ip_type` family of that decision value, not a second copy of the origin string. Forget SHALL still delete by slot key. The `active_decisions` POST item SHALL still send lists-rewritten origin names via `OriginName` (or the leftover origin string when intern overflowed). Live, none, and AppSec-only modes SHALL omit this map. The intern table owner is DecisionStore; the reporter MUST NOT own a second intern table.

#### Scenario: Stream IP ban still posts origin name
- **WHEN** stream applies one Ip ban whose value is `1.2.3.4` and origin is `crowdsec`
- **THEN** `active_decisions` includes 1 with `origin=crowdsec` and `ip_type=ipv4`

#### Scenario: Forget drops that slot
- **WHEN** stream later deletes that same Ip slot
- **THEN** the next `active_decisions` window omits that record
