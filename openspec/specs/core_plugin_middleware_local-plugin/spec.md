## Purpose

Defines this unpublished fork’s Traefik load contract: the manifest import matches `go.mod`, the display name is distinct from upstream, and in-tree runnable examples load the tree as a local plugin instead of a catalog download.

## Requirements

### Requirement: Go module path is this fork
`go.mod` `module` SHALL be `github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin`. Every in-tree Go import of this module SHALL use that path. The root package clause SHALL stay `crowdsec_bouncer_traefik_plugin`. The manifest MUST NOT set `basePkg`.

#### Scenario: Module line matches the fork
- **WHEN** a reviewer inspects `go.mod` and a `pkg/` import of this module
- **THEN** both name `github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin`
- **AND** neither names `github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin`

### Requirement: Manifest import matches go.mod
`.traefik.yml` `import` SHALL equal the `go.mod` `module` path. It MUST NOT keep `github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin`.

#### Scenario: Import equals the module
- **WHEN** Traefik reads this tree’s `.traefik.yml`
- **THEN** `import` is `github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin`

### Requirement: Display name distinguishes from upstream
`.traefik.yml` `displayName` SHALL be `CrowdSec Bouncer Traefik Plugin (david-garcia-garcia)`. It MUST NOT be empty. It MUST NOT equal `Crowdsec Bouncer Traefik Plugin`.

#### Scenario: Display name is the fork string
- **WHEN** a reviewer inspects `.traefik.yml`
- **THEN** `displayName` is `CrowdSec Bouncer Traefik Plugin (david-garcia-garcia)`

### Requirement: In-tree loads use localPlugins at go.mod
In-repo runnable Traefik compose, e2e harnesses, Kubernetes values, and binary-vm static config that load this tree SHALL register `localPlugins` (CLI `experimental.localplugins` or YAML `experimental.localPlugins`) under alias `bouncer` with `moduleName` equal to the `go.mod` module, and SHALL place sources at `plugins-local/src/<that module>` (bind-mount, symlink, or documented operator copy). They MUST NOT set `experimental.plugins.bouncer.version` for this module. They MUST NOT use `github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin` as this tree’s `moduleName`. The README working static example SHALL be that localPlugins form. It MUST NOT present a catalog `version: vX.Y.Z` of this module as the working install.

#### Scenario: Catalog-form compose loads this tree locally
- **WHEN** root `docker-compose.yml` or an `examples/*/docker-compose.yml` that used catalog `plugins.bouncer` plus `version=v1.7.1` is started from this tree
- **THEN** Traefik registers `localPlugins.bouncer` at the `go.mod` module path with a bind-mount of the repository root
- **AND** that file does not set a catalog `version=` for this module

#### Scenario: Already-local e2e keeps the new path
- **WHEN** real e2e or mock e2e starts Traefik
- **THEN** `plugins-local/src/` and `moduleName` use `github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin`
- **AND** alias `bouncer` is unchanged
