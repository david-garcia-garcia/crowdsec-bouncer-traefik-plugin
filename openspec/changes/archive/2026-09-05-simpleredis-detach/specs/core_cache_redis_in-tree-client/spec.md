## MODIFIED Requirements

### Requirement: In-tree package is the Redis client
The plugin SHALL import `github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/simpleredis` for Redis GET/SET/DEL (and SHALL expose `MGet` on that package). Runtime SHALL NOT import `github.com/maxlerebourg/simpleredis`. `pkg/simpleredis` is this plugin’s Redis client (pooled connections, RESP arrays, `Init`/`Get`/`Set`/`Del`/`MGet`). It MUST NOT be required to match an outside simpleredis repository or pull request. `pkg/simpleredis` MUST NOT contain `LICENSE` or `SOURCE` pin files.

#### Scenario: Cache compiles against pkg/simpleredis
- **WHEN** a reviewer inspects `pkg/cache/cache.go` and `go.mod`
- **THEN** the cache imports the in-tree package and `go.mod` does not require `github.com/maxlerebourg/simpleredis`

#### Scenario: MGet is available without cache calling it
- **WHEN** a caller uses `pkg/simpleredis`
- **THEN** `MGet([]string) ([][]byte, error)` exists

#### Scenario: Package has no upstream pin files
- **WHEN** a reviewer inspects `pkg/simpleredis`
- **THEN** `LICENSE` and `SOURCE` are absent
