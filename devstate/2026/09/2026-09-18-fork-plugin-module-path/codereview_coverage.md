# Test coverage

1. [hard] Ticket job unproven — `go.mod:1` / `.traefik.yml:5` — DestBranch identified as maxlerebourg; retargeted tests import the new path but assert bouncer behavior, not that `go.mod` `module` and `.traefik.yml` `import` / `displayName` are this fork (revert of those two files stays green)
   → Assert `go.mod` module, `.traefik.yml` `import`, and `displayName` are `github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin` / `CrowdSec Bouncer Traefik Plugin (david-garcia-garcia)`
   Status: done
   Argument: 5889a22 added zzz_module_path_test.go; later moved to pkg/configuration so yaegi test . does not interpret it. TestForkModulePathMatchesManifest asserts go.mod module, .traefik.yml import, and displayName.
