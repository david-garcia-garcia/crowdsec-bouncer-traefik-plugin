---
url: https://github.com/david-garcia-garcia/traefik-modsecurity/blob/e860d2494f41d49172f2d8aae916615c8ee356e1/scripts/integration-tests.BodySize.Tests.ps1
title: integration-tests.BodySize.Tests.ps1
fetched: 2026-10-12
authority: source
ref: github.com/david-garcia-garcia/traefik-modsecurity@e860d2494f41d49172f2d8aae916615c8ee356e1:scripts/integration-tests.BodySize.Tests.ps1
---

BeforeAll: TestHelpers, wait WAF healthy, Traefik API /protected /pool-test.

Describe "MaxBodySizeBytes Configuration Tests (Large Bodies)": 16MB POST /large-body-test status < 500; 21MB → 413.

Describe "Chunked POST vs pool threshold": /pool-test 2048 chunked → 200; 6144 chunked → 413.

Describe "MaxBodySizeBytes Status Header Tests": /protected 2KB POST → 413 and access log request_X-Waf-Status=blocked (pooled path).

Describe "Body Size Limit Tests - usePool=false Path": /pool-test sizes 1014/1024/1034/5120/5130 expect 200/200/200/200/413; 6KB → 413 and backend not called (blocked header).

Describe "Chunked POST vs pool threshold": duplicate of the earlier Describe (same two Its).
