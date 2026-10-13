# Devdocs impact
change: compact-liveslot-elapsedsec

## Units
- DecisionStore memory slot expiry — subsystem — `pkg/decisionstore` LiveSlot / PublishTick
- Stream apply — pattern — `pkg/lapi/client_stream.go` defer PublishTick

## Findings
- [x] language-gap — DecisionStore — no Language term for elapsed slot clock (`core_plugin_decisionstore.md`)
- [x] stale-usage — DecisionStore — memory How-to omitted int32 elapsed ExpiresAt and PublishTick(0) sweep
- [x] stale-usage — Stream apply — pattern snippet still used `time.Now().Unix()` for PublishTick
