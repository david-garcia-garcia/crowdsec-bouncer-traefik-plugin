## Purpose

Defines this fork’s Traefik load contract: the manifest import matches `go.mod`, the display name is distinct from upstream, examples that run from a checkout load the tree as a local plugin, and install examples that do not ship the tree download a pinned release from the Traefik plugin catalog.

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

### Requirement: Checkout loads use localPlugins at go.mod
In-repo runnable Traefik compose and e2e harnesses that load this checkout SHALL register `localPlugins` (CLI `experimental.localplugins` or YAML `experimental.localPlugins`) under alias `bouncer` with `moduleName` equal to the `go.mod` module, and SHALL place sources at `plugins-local/src/<that module>` (bind-mount or symlink). They MUST NOT set `experimental.plugins.bouncer.version` for this module. They MUST NOT use `github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin` as this tree’s `moduleName`.

#### Scenario: Compose loads this checkout locally
- **WHEN** root `docker-compose.yml` or an `examples/*/docker-compose.yml` is started from this tree
- **THEN** Traefik registers `localPlugins.bouncer` at the `go.mod` module path with a bind-mount of the repository root
- **AND** that file does not set a catalog `version=` for this module

#### Scenario: Already-local e2e keeps the new path
- **WHEN** real e2e or mock e2e starts Traefik
- **THEN** `plugins-local/src/` and `moduleName` use `github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin`
- **AND** alias `bouncer` is unchanged

### Requirement: Install examples use the catalog at go.mod
Install examples that do not ship this tree to the Traefik host (`examples/kubernetes` Helm values, `examples/binary-vm` static config) SHALL register `experimental.plugins.bouncer` with `moduleName` equal to the `go.mod` module and `version` pinned to a release tag that the Traefik plugin catalog serves. They MUST NOT use `github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin` as `moduleName`. The README static configuration SHALL show this catalog form, and MAY show the `localPlugins` form next to it for a checkout.

#### Scenario: Kubernetes values download a release
- **WHEN** `examples/kubernetes/traefik/values.yml` is rendered by the Traefik chart
- **THEN** Traefik receives `--experimental.plugins.bouncer.moduleName=github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin` and `--experimental.plugins.bouncer.version=vX.Y.Z`

#### Scenario: Binary VM downloads a release
- **WHEN** a reviewer inspects `examples/binary-vm/files/traefik/traefik.yml`
- **THEN** `experimental.plugins.bouncer` names the `go.mod` module and a pinned `version`
- **AND** it does not register `localPlugins.bouncer`
