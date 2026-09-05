## Purpose

Keep the Traefik Config bag, file secrets, templates, and validation in `pkg/configuration`, and build LAPI/AppSec client TLS next to those HTTP clients, without changing operator YAML or TLS outcomes.

## ADDED Requirements

### Requirement: Traefik Config stays the public plugin bag
The plugin SHALL keep `CreateConfig` on the module-root package returning `*configuration.Config`. Public JSON tags on `Config` SHALL stay. Validation rules SHALL stay. Operators MUST NOT need a new or renamed Traefik key for this change.

#### Scenario: CreateConfig still returns configuration.Config
- **WHEN** Traefik loads the plugin and calls `CreateConfig`
- **THEN** the result is a `*configuration.Config` with the same JSON field names as on dest `master`

#### Scenario: Invalid mode still fails validate
- **WHEN** `ValidateParams` runs with `CrowdsecMode` set to a value other than none, live, stream, alone, or appsec
- **THEN** validation returns an error

### Requirement: File secrets and templates stay on the Config package
Reading a `*File` sibling then the inlined string, and compiling ban/captcha templates, SHALL remain functions of `pkg/configuration`. Callers outside that package MUST NOT reimplement file-or-inline secret reads.

#### Scenario: LAPI key file still wins
- **WHEN** `CrowdsecLapiKeyFile` points at a readable file and `CrowdsecLapiKey` is also set
- **THEN** the resolved secret is the trimmed file contents

### Requirement: LAPI and AppSec HTTP use Config TLS fields at client construction
Building the LAPI and AppSec `http.Client` SHALL apply TLS from the same Config fields as dest `master` (scheme, insecure skip, custom CA PEM, client cert/key). When scheme is not https, TLS SHALL be an empty `tls.Config`. When https and no custom CA, RootCAs SHALL stay nil so crypto/tls uses the system pool. When https and a custom CA PEM, RootCAs SHALL contain that PEM. When insecure skip is set, InsecureSkipVerify SHALL be true. Config validation MAY still parse a custom LAPI CA PEM at validate time without constructing those HTTP clients.

#### Scenario: HTTP scheme yields empty TLS
- **WHEN** Crowdsec LAPI scheme is http
- **THEN** the LAPI client TLS config has nil RootCAs and InsecureSkipVerify false

#### Scenario: HTTPS without CA uses the system pool
- **WHEN** Crowdsec LAPI scheme is https and no custom CA is configured
- **THEN** the LAPI client TLS config has nil RootCAs

#### Scenario: HTTPS custom CA is loaded
- **WHEN** Crowdsec LAPI scheme is https and a valid CA PEM is configured
- **THEN** the LAPI client TLS config RootCAs is non-nil

#### Scenario: HTTPS insecure skip
- **WHEN** Crowdsec LAPI scheme is https and TLS insecure verify is true
- **THEN** the LAPI client TLS config has InsecureSkipVerify true

#### Scenario: Garbage CA is rejected
- **WHEN** Crowdsec LAPI scheme is https and the custom CA is not valid PEM
- **THEN** TLS construction returns an error
