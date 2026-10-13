## MODIFIED Requirements

### Requirement: Yaegi constructors stay on the module-root package
The plugin SHALL export `CreateConfig` and `New` from the package Traefik loads for `.traefik.yml` `import` (the module root). `New` SHALL take Traefik’s constructor context and MUST NOT ignore it.

#### Scenario: Fork import still constructs
- **WHEN** Traefik loads `github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin`
- **THEN** `CreateConfig` and `New` exist on that package
- **AND** `New` receives a non-ignored context used as the reclaim holder
