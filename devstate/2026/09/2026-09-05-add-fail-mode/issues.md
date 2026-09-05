# Issues

- [ ] note large  public `crowdsecAppsecFailureBlock` / `crowdsecAppsecUnreachableBlock` → `appsecFailMode`
  Why: replacing published Traefik plugin keys is a contract break. Explore assumed replace; human can keep the bools as aliases.
- [ ] note large  public `updateMaxFailure` vs new `lapiFailMode`
  Why: they overlap stream unavailability. Explore assumed wrap (keep the counter). Human can instead delete or hide `updateMaxFailure`.
