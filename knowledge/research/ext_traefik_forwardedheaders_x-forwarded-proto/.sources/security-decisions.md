---
url: https://doc.traefik.io/traefik/master/contributing/security-decisions/
title: Traefik Security Decisions — Forwarded Headers and Client Identity
fetched: 2026-09-18
authority: official
---

The trust boundary for forwarded headers is entrypoint-level. forwardedHeaders.trustedIPs and forwardedHeaders.insecure decide once, at the entrypoint, before any middleware runs, whether a client's forwarding headers are trusted.

Traefik deliberately does not re-decide per middleware: re-deciding in each middleware is the design mistake they are avoiding, not an omission.

A middleware passing through a header the entrypoint accepted is behaving as designed.

In scope: a path that reintroduces or reconstructs a trusted value after entrypoint sanitisation so the entrypoint's decision no longer holds; a middleware that makes a pre-authentication decision on a header the operator declared untrusted.
