# Issues

- [x] note large  public `crowdsecAppsecFailureBlock` / `crowdsecAppsecUnreachableBlock` / `crowdsecAppsecUnreadableBodyBlock` → `crowdsecAppsecFailureAction`
  Why: taken in this change — the three bools are gone; `crowdsecAppsecFailureAction` is the public key.
- [x] note large  public `updateMaxFailure` vs new `crowdsecLapiFailureAction`
  Why: taken in this change — both kept (poll counter vs fallback action).
