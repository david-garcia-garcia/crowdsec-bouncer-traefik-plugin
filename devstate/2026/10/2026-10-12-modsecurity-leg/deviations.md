# Deviations

- [x] taken  dest `modsec*` stems instead of source `modSecurityUrl` camelCase
  Asked: absorb traefik-modsecurity (its public YAML keys).
  Instead: dest naming family `modsecEnabled`, `modsecUrl`, `modsecInstanceName`, `bouncerModsecFailMode` (same stems as `appsec*` / `lapi*` / `captcha*`).
  Owner: `pkg/configuration/configuration.go`
  Why: honouring the source key names would add a second naming family next to the dest public surface.
  By: explore
  Requester: not asked

- [x] taken  fold source `bypassRules` into `bouncerActionRules`
  Asked: absorb the source plugin, which has `bypassRules` method+pathRegexp entries.
  Instead: `bypassModsec` / `bypass` tokens on the existing action-rule owner; no parallel list.
  Owner: `pkg/httprule/action.go`
  Why: honouring a second skip list would add a variation point to a unit whose job is uniform request-rule skips.
  By: explore
  Requester: not asked