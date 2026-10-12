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
- [x] taken  dest `modsecBodyLimit` `0` unlimited instead of source Prepare fill
  Asked: absorb traefik-modsecurity (Prepare treats body-size `0` as omit and fills 8 MiB).
  Instead: omitted default 8 MiB (source CreateConfig); `0` is unlimited like `appsecBodyLimit`.
  Owner: `pkg/configuration/configuration.go`
  Why: honouring source zero-means-omit would add a second zero rule next to AppSec's unlimited zero.
  By: propose
  Requester: not asked
