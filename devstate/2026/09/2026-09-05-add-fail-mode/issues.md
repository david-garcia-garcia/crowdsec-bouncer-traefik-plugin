# Issues

- [ ] note large  public `crowdsecAppsecFailureBlock` / `crowdsecAppsecUnreachableBlock` / `crowdsecAppsecUnreadableBodyBlock` → `appsecFailureAction`
  Why: human wants one AppSec action. Published Traefik keys go away; leftover YAML is ignored or must error at validate.
- [ ] note large  public `updateMaxFailure` vs new `lapiFailureAction`
  Why: they overlap stream unavailability. Explore still assumed wrap (keep the counter).
