---
url: https://github.com/david-garcia-garcia/traefik-modsecurity/blob/main/pkg/modsecurity/serve.go
title: traefik-modsecurity pkg/modsecurity/serve.go (health integration)
fetched: 2026-09-06
authority: source
ref: github.com/david-garcia-garcia/traefik-modsecurity@645f4a25d5023fc42e615e02240cab29799b39c5:pkg/modsecurity/serve.go
---

Before sidecar call: if healthTracker.IsUnhealthy(), skip HTTP and serveFailClosedOrNext.
On sidecar transport failure: healthTracker.RecordFailure().
Client disconnect (context.Canceled) does not RecordFailure.
