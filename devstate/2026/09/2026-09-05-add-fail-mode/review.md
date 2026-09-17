# Review

## prepare (2026-09-05)
phase: prepare
findings: none
fixed: none
skipped: explore (caller stop); propose and later phases

## explore (2026-09-05)
phase: explore
findings: UpdateMaxFailure fights LapiFailMode; AppSec bools fight AppsecFailMode; spec defaults passthrough vs plugin fail-closed
fixed: none (stop at explore)
skipped: propose and later phases (caller)


## implement (2026-09-05)
phase: implement
findings: none
fixed: Crowdsec-prefixed failure actions applied (b50f987)
skipped: CI still in progress at card time

## codereview (2026-09-05)
phase: codereview
findings: empty failure action accepted; live ban ReasonTECH vs ReasonLAPI; gofmt restyle
fixed: reject empty; live ReasonLAPI (5f427bf)
skipped: gofmt composite-literal alignment

## destateimpact (2026-09-05)
phase: destateimpact
findings: Failure action Language gap; middleware/appsec usage
fixed: Language + How-to/Gotcha on core_plugin_middleware and core_plugin_appsec
skipped: none

## archive (2026-09-05)
phase: archive
findings: none
fixed: synced two new specs + bot-detection fold; moved change to archive
skipped: FindSpecHost Task (verdicts already on destate/specs.md)
