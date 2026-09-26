# Dead

1. [hard] Dead branch or constant — `pkg/bouncer/remediation_header.go:64` — `headerReasonFromOrigin` cases for `OriginPluginTechCacheFail`, `OriginPluginTechGetRemoteFail`, and `OriginPluginTechTrustIPFail` have no production caller after ServeHTTP started passing `headerReasonCacheFail` and `headerReasonUnparseableRequest` directly
   Quote:
      ```
      case lapi.OriginPluginTechCacheFail:
      	return headerReasonCacheFail
      case lapi.OriginPluginTechGetRemoteFail, lapi.OriginPluginTechTrustIPFail:
      	return headerReasonUnparseableRequest
      ```
   Note:
      ```
      rg headerReasonFromOrigin OriginPluginTechCacheFail OriginPluginTechGetRemoteFail OriginPluginTechTrustIPFail -- glob *.go excluding tests docs examples openspec knowledge devstate .cursor
      Production headerReasonFromOrigin call sites: bouncer.go applyLapiFailureAction, handleRemediationServeHTTP, handleCaptchaKindServeHTTP with OriginPluginLapiFailure, OriginPluginTechStreamFail, OriginPluginForcedDecision, OriginPluginAppsecFailure, or LAPI origins.
      Cache-fail and unparseable origins only hit handleBanServeHTTP / banOrWarnForcedCaptcha with the reason token already chosen (bouncer.go:458,463,514). Remaining mapper rows for those three origins: zzz_remediation_header_test.go TestHeaderReasonFromOrigin.
      ```
   Fix: Delete those three mapper cases; drop the matching TestHeaderReasonFromOrigin rows; keep the constants at the ServeHTTP call sites
   Status: done
   Argument: Deleted the three mapper cases; dropped matching TestHeaderReasonFromOrigin rows; ServeHTTP still passes headerReasonCacheFail and headerReasonUnparseableRequest.
