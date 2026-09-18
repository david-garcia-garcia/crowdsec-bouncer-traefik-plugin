## prepare (2026-09-18)
phase: prepare
findings: none
fixed: none
skipped: no Task subagent used; prepare wrote the bus in-process

## explore (2026-09-18)
phase: explore
findings: none
fixed: none
skipped: no Task subagent used; no research write (AppSec protocol and Traefik New already covered); no usage write (enabled gate is not dest yet)

## propose (2026-09-18)
phase: propose
findings: none
fixed: none
skipped: no Task subagent used; no research write; no usage write (enabled gate is not dest yet; deferred to devdocs-impact)

## implement (2026-09-18)
phase: implement
findings: none
fixed: gated validateAppsecURLKeyAndTLS on CrowdsecAppsecEnabled in every mode; dropped validateLapiAndAppsecConnection; flipped leftover-CA dest test; added alone/live on-fail and off-leftover cases
skipped: no Task subagent used; no new spec folder; usage packet deferred to devdocs-impact; no comments.md FIX rows
