---
url: https://github.com/david-garcia-garcia/traefik-modsecurity/blob/main/pkg/health/tracker.go
title: traefik-modsecurity pkg/health/tracker.go
fetched: 2026-09-06
authority: source
ref: github.com/david-garcia-garcia/traefik-modsecurity@645f4a25d5023fc42e615e02240cab29799b39c5:pkg/health/tracker.go
---

Tracker counts failures in a tumbling window; trips unhealthy after threshold; auto-recovers after backoffTimeout.
IsUnhealthy uses lockless fast path when not shutdown.
failureThreshold < 0 never trips.
