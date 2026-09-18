# Standards

1. [judgement] Duplicated Code — `pkg/configuration/zzz_configuration_test.go:217` — `TestHunt_ValidateParams_aloneModeStillRejectsInvalidAppsecCA` repeats the table row at `:201` (same alone + CAPI + HTTPS + garbage CA → error)
   → Keep the named hunt proof or the table row, not both
   Status: skipped
   Argument: judgement; hunt name is the ticket proof and the table row is the spec scenario.
