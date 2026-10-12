---
url: https://github.com/david-garcia-garcia/traefik-modsecurity/blob/e860d2494f41d49172f2d8aae916615c8ee356e1/scripts/TestHelpers.ps1
title: TestHelpers.ps1
fetched: 2026-10-12
authority: source
ref: github.com/david-garcia-garcia/traefik-modsecurity@e860d2494f41d49172f2d8aae916615c8ee356e1:scripts/TestHelpers.ps1
---

Helpers used by both Pester files: Get-TraefikContainerName (`*-traefik-1`), Get-WafContainerName (compose service label `waf`, not waf-5xx), Get-IntegrationStackComposeFiles (same mapping as the runner), Wait-ForWafHealthy, Wait-ForWafAllowPath (GET /protected 200), Wait-ForThresholdRouteInspecting (SQLi on /threshold-test must 4xx), Invoke-ThresholdTestFailOpenTrip (`docker stop -t 0` then 3 requests + pass-through), Invoke-SafeWebRequest (SkipHttpErrorCheck), Invoke-TcpHttpRequest, Invoke-ChunkedHttpRequest, Get-TraefikAccessLogEntries, Get-WafAuditLogRecords / Get-WafAuditClientIp / Get-WafAuditHost, New-RequestBodyOfSizeBytes, Test-WafBlocking / Test-MaliciousPatterns / Test-BypassPatterns, reclaim YAML rewrite + slog scrape, Invoke-WebSocketEcho, Invoke-AllowPathBombardier (reads INTEGRATION_STACK).
