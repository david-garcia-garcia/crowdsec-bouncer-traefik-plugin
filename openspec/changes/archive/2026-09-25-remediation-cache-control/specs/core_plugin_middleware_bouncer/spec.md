## ADDED Requirements

### Requirement: Ban page sets Cache-Control
When the bouncer writes the operator ban page, the response SHALL set `Cache-Control` to `no-cache, no-store`. It MUST set that header before `WriteHeader`. HEAD and empty-body (nil template) bans SHALL carry the same header.

#### Scenario: GET ban includes Cache-Control
- **WHEN** `handleBanServeHTTP` writes a GET ban
- **THEN** `Cache-Control` is `no-cache, no-store`

#### Scenario: HEAD ban includes Cache-Control
- **WHEN** `handleBanServeHTTP` writes a HEAD ban
- **THEN** `Cache-Control` is `no-cache, no-store`
- **AND** the body is empty

#### Scenario: Nil template ban includes Cache-Control
- **WHEN** `handleBanServeHTTP` writes a ban and the ban template is nil
- **THEN** `Cache-Control` is `no-cache, no-store`
