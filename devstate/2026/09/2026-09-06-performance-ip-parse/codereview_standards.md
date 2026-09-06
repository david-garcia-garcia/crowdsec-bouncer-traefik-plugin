# Standards

1. [hard] Leave a trail — `pkg/ip/network.go:26` — `Family` comment still says “for an address GetRemoteIP already returned” after the diff moves request-path `ip_type` to `FamilyOfIP(parsedIP)` and docs relegate `Family` to decision values
   → Reword the `Family` comment to name decision-string classification and point request-path callers at `FamilyOfIP`
   Status: done
   Argument: reworded Family comment to decision-string classification; request-path callers use FamilyOfIP (c45bad8).
