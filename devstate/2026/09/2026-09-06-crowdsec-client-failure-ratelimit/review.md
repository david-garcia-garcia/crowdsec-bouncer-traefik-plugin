## prepare (2026-09-06)
phase: prepare
findings: qualified-with-gaps; 5 unknowns on failure signals, defaults, stream interaction
fixed: requirement.md, research ext_traefik-modsecurity_health_tracker, stub PR #55
skipped: explore/propose/implement

## explore (2026-09-06)
phase: explore
findings: tumbling-window Tracker on reclaimed LAPI/AppSec clients; leaky-bucket rejected; 2 assumed (signals, defaults 30/30/5)
fixed: explore.md decisions; identity-owner is GetRemoteIP (no reconstruct)
skipped: product code

## propose (2026-09-06)
phase: propose
findings: apply-ready crowdsec-client-failure-backoff; FindSpecHost new tracker/lapi-backoff/appsec-backoff, fold appsec_client
fixed: openspec/changes/crowdsec-client-failure-backoff/, specs.md
skipped: product code
