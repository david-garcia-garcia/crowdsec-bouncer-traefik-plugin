# Requirement
IssueKey: 2026-09-06-domain-lapi-appsec

## Problem
`pkg/crowdsecconnection` is one reclaim type for two CrowdSec products. LAPI (decisions/remediation: none, live, stream, alone; `crowdsecLapi*`) and AppSec (HTTP WAF; `crowdsecAppsec*`) share the package, struct, reclaim identity, and `Prepare`. Callers cannot tell which job they are holding. The archived spec `core_plugin_connection_source-files` already froze AppSec as a same-package file, which is the coupling this ticket wants undone.

## Current (code)
- `pkg/crowdsecconnection/connection.go` `CrowdsecConnection` holds LAPI/CAPI fields, stream/metrics tickers, isolated cache, Range membership, **and** AppSec scheme/host/path/key/bodyLimit plus `httpAppsecClient`. Package comment says “one Crowdsec LAPI/CAPI identity.”
- `Prepare` (`connection.go`) resolves LAPI key (or CAPI host in `alone`) and, when AppSec key is empty, copies `CrowdsecLapiKey` into `CrowdsecAppsecKey`; AppSec scheme also falls back to LAPI scheme.
- `New` builds both TLS clients; `CrowdsecMode == appsec` returns before cache/stream start so the same type is used as an AppSec-only connection (`connection.go`).
- `pkg/crowdsecconnection/connection_appsec.go` owns `AppsecQuery`, `AppsecResponse`, `AppsecPolicy`, `ErrFailureCaptcha`. `pkg/bouncer/bouncer.go` calls `b.conn.AppsecQuery` on the pass path when `crowdsecAppsecEnabled`.
- Live/none reclaim identity includes AppSec host/key/TLS (`identity.go`). Stream session is LAPI URL+key only, but `streamSettings` still includes AppSec knobs for warn-and-wire (`session.go`).
- `crowdsecMode` enum mixes LAPI modes (`none`/`live`/`stream`/`alone`) with `appsec` (`pkg/configuration/configuration.go`). `crowdsecAppsecEnabled` is orthogonal and can run on stream/live.
- Spec `openspec/specs/core_plugin_connection_source-files/spec.md` SHALL keep `AppsecQuery` on `package crowdsecconnection` and forbids a new module path for those jobs.
- Public Traefik keys already split: `crowdsecLapi*` vs `crowdsecAppsec*` (`configuration.go`).

## Desired
- Rename `pkg/crowdsecconnection` to a LAPI-owned package (`lapi` as the named target).
- Move `connection_appsec` (AppSec HTTP query, envelope, failure mapping) to its own package.
- LAPI package owns none/live/stream/alone, decisions/remediation, stream cursor, usage-metrics, cache prefix. AppSec package owns the WAF round-trip (host, key, TLS, body limit, failure action).
- Do not change operator keys (`crowdsecLapi*`, `crowdsecAppsec*`) or runtime verdict behavior.

## Affected
- `pkg/crowdsecconnection/` (rename + extract)
- `plugin.go`, `plugin_test.go`
- `pkg/bouncer/bouncer.go`, `pkg/bouncer/bouncer_test.go`
- `openspec/specs/core_plugin_connection_source-files/spec.md` (must be superseded)
- `knowledge/devdocs/core_plugin_middleware.md`, `core_plugin_appsec.md`, and other packets that cite `pkg/crowdsecconnection`
- `.golangci.yml` depguard paths for `pkg/crowdsecconnection`

## Out of scope
- Changing Traefik JSON/YAML keys or defaults.
- Changing AppSec protocol, challenge relay, or LAPI stream/live lookup behavior.
- Splitting `pkg/configuration` into LAPI vs AppSec config types.
- Renaming `crowdsecMode: appsec` or `crowdsecAppsecEnabled` (unless explore decides the mode value is in scope).
- Plugin lifecycle / reclaim table mechanics except as required to own the two packages (`2026-09-06-plugin-lifecycle-lapi` is a different ticket).
- Redis / cache / decisionscope ownership.

## Unknowns
- AppSec package name (human said “its own package”; not named).
- Whether AppSec is reclaimed separately from LAPI, or Bouncer holds two pointers on one Traefik New.
- Whether `CrowdsecConnection` type name survives inside `package lapi`.
- Whether `Prepare` LAPI-key → AppSec-key fallback stays (behavior) after the package split.
- How `crowdsecMode: appsec` (skip LAPI) sits next to `crowdsecAppsecEnabled` (run AppSec on a LAPI mode).

## Tensions
- Archived spec `core_plugin_connection_source-files` forbids a new import path and requires `AppsecQuery` on `CrowdsecConnection`. This ticket asks the opposite.
- Stream warn-and-wire first-wins currently includes AppSec client knobs on the LAPI session. Split reclaim could change who “wins” AppSec host/key without a behavior ticket.
- `AppsecMode` lives in the LAPI mode enum but means “do not talk to LAPI.”
- Official AppSec protocol notes the bouncer API key is often the same as LAPI; this plugin already has a distinct `crowdsecAppsecKey` with LAPI fallback (`Prepare`).
