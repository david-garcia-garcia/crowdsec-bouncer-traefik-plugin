---
url: https://github.com/david-garcia-garcia/traefik-modsecurity/blob/e860d2494f41d49172f2d8aae916615c8ee356e1/scripts/integration-tests.Tests.ps1
title: integration-tests.Tests.ps1
fetched: 2026-10-12
authority: source
ref: github.com/david-garcia-garcia/traefik-modsecurity@e860d2494f41d49172f2d8aae916615c8ee356e1:scripts/integration-tests.Tests.ps1
---

BeforeAll dotsources TestHelpers.ps1. BaseUrl http://localhost:8000, TraefikApiUrl http://localhost:8080. Waits for Traefik API, /bypass, /protected, /large-body-test, /remediation-test, /error-test, /force-test, /pool-test, /threshold-test, /chain-retry, /retry-force, /chain-buffer, /reclaim-a, /reclaim-b, /ws-echo.

Describe families in file order:
- "ModSecurity Plugin Basic Functionality"
- "WAF Protection Tests"
- "Remediation Response Header Tests"
- "Bypass Functionality Tests"
- "Performance and Health Tests"
- "Performance Comparison Tests"
- "MaxBodySizeBytes Configuration Tests"
- "DenyVerbsWithBody Configuration Tests"
- "WAF Health Tracker Threshold Tests"
- "Traefik middleware chain with WAF"
- "Plugin reclaim logs" (tag Reclaim)
- "WebSocket through WAF middleware"
- "Sidecar 5xx is not a copied block"
- "Error Handling and Edge Cases"
- "Allow-path throughput"
