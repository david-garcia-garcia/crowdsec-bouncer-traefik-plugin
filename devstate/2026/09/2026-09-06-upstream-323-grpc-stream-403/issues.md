# Issues

- [ ] take small  restore `CrowdsecAppsecUnreadableBodyBlock` (`crowdsecAppsecUnreadableBodyBlock` / lua `APPSEC_DROP_UNREADABLE_BODY`)
  Why: human RETHINK on PR #51. Default false keeps gRPC pass-through; true is opt-in drop independent of `CrowdsecAppsecFailureAction`.
