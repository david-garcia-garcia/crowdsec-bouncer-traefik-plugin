# Spec

1. [wrong] AppSec Query applies FailureAction before Allow — `pkg/appsec/query.go:139` — Query builds the outbound AppSec request (and can ban an unreadable POST, PUT, or PATCH body) before `Allow`, so a tripped gate still applies `bouncerAppsecFailureAction` instead of skip-pass
   Fix: Call `Allow` before `newAppsecForwardRequest` so a denied Allow cannot take the unreadable-body FailureAction path
   Status: done
   Argument: Query admits before newAppsecForwardRequest
