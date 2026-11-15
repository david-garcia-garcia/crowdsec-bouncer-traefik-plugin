# Devdocs impact
change: count-challenge-drop-once, terminate-unanswered-challenge-paths

## Units
- AppSec challenge relay — subsystem — `pkg/bouncer/bouncer.go` `handleAppsecResponseServeHTTP`
- AppSec challenge prefix guard — subsystem — `pkg/bouncer/bouncer.go` `serveAppSec` / `answerAppSec`
- Usage-metrics dropped window — subsystem — `pkg/lapi` `IncDropped` / `IncDroppedBytes`

## Findings
- [x] stale-usage  AppSec challenge relay — `core_plugin_appsec` How to use did not say the relay skips `recordDropped` under `/crowdsec-internal/challenge/`
- [x] stale-usage  AppSec challenge prefix guard — `core_plugin_appsec` How to use named the removed helper `isAppsecChallengePath`; now `isCrowdsecChallengeCallbackPath` (the 404 bullet itself came with PR 196)
- [x] stale-usage  Usage-metrics dropped window — `core_plugin_lapi_usage-metrics` How to use said `IncDropped` on each remediating response, with no relay callback exception
