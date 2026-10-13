# Explore
IssueKey: 2026-09-05-add-real-e2e

## Concepts

**Mock e2e** — `tests/e2e/mock/`: Traefik **binary** + `mocklapi`. No Docker, no Crowdsec. CI already runs this (`make e2e_mock`, `.github/workflows/e2e.yml`).

**Real-stack / Docker e2e** — Traefik **container** + **Crowdsec** container, plugin loaded via Traefik `experimental.localPlugins` from a bind mount of the repo. Decisions injected with `cscli decisions add`. This is what `master` documents as missing (`Makefile` comments, `tests/e2e/mock/README.md` pointing at upstream #333).

**Client IP in tests** — scenarios send `X-Forwarded-For`. Traefik `forwardedHeaders` plus the plugin’s `forwardedHeadersTrustedIPs` already own the address the bouncer uses. Tests must not parse `RemoteAddr` as a second source.

```
  curl + X-Forwarded-For
           │
           ▼
  Traefik container (localPlugins bind-mount)
           │  forwardedHeaders + trusted CIDR
           ▼
  Plugin ServeHTTP ── LAPI ── Crowdsec container
           │                     ▲
           │                     └── cscli decisions add
           ▼
  whoami / ban / captcha assertion
```

## Decisions

Keep **mock e2e** (`tests/e2e/mock/`, bash, CI `e2e_mock`) and add the **Pester real-stack suite** from closed PR 273 as a **separate** suite. Do not land upstream PR 333’s bash `tests/e2e/scenarios/` — that is a third layout, not this ticket.

Human (2026-09-05): Pester is a different e2e from master’s mock; use PowerShell like the original proposal; adjust CI so those tests run.

Pin images to this tree’s examples: `traefik:v3.7.11`, `crowdsecurity/crowdsec:v1.7.8`. Replace 273’s `crowdseclapiurl` labels with `crowdseclapishost` (current plugin field; default is already `crowdsec:8080`).

Run Pester in GitHub Actions on this fork in addition to mock. Keep `e2e_mock`. Do not change bouncer runtime Go.

This `origin/master` has **no** `openspec/` tree. Propose bootstraps `openspec/specs/domains.md` and a `build_e2e_*` spec.

## Open questions

- Q: Which implementation to land — Pester 273, bash 333, or a hybrid?
  Decision: resolved — Pester + Docker Compose from PR 273 as a separate real-stack suite; keep mock e2e; do not land bash 333.
  By: implement

- Q: Should GitHub Actions in this repo run the Docker suite, or keep it local-only like 333?
  Decision: resolved — run `./Test-Integration.ps1` in CI on this fork; keep `make e2e_mock` as a separate job.
  By: implement

- Q: Which Traefik / Crowdsec image tags?
  Decision: assumed — `traefik:v3.7.11` and `crowdsecurity/crowdsec:v1.7.8` (this tree’s `docker-compose.yml` / examples), not 333’s `traefik:v3.7.1`.
  By: explore

- Q: Who already owns the client address the bouncer remediates in these tests?
  Decision: assumed — Traefik `forwardedHeaders` plus the plugin’s `forwardedHeadersTrustedIPs` (333 uses `forwardedHeaders.insecure=true` and trusted `172.16.0.0/12`). Tests send `X-Forwarded-For` only. Do not derive the client IP from `RemoteAddr` in the harness.
  By: explore

- Q: Should push workflows also list `master` (today they list `main` only; `pull_request` has no branch filter)?
  Decision: assumed — do not change push branch filters; PR into `master` already runs Main and E2E jobs.
  By: explore

- Q: Keep 333’s well-known test LAPI key `40796d93c2958f9e58345514e67740e5`?
  Decision: assumed — yes; it is the fixture 333 and 273 already use with `BOUNCER_KEY_TRAEFIK`. Not a production secret.
  By: explore

- Q: Main CI on this fork fails `yaegi_test` because checkout uses `github.repository` (`david-garcia-garcia/...`) while the module path is `github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin`. Can this PR go green without touching Main?
  Decision: assumed — pin checkout path in `.github/workflows/main.yml` to the Go module path so Yaegi finds the plugin on this fork. Required for the caller’s “CI succeeds” done-when. Do not change bouncer Go.
  By: explore
