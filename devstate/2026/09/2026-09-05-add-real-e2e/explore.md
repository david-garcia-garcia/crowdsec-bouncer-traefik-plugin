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

Port **upstream PR 333** (`feat/e2e-docker`, bash + Compose under `tests/e2e/scenarios/`) onto this `master`, not the closed Pester PR 273.

Why: `master` already describes that layout (`make e2e`, `tests/e2e/scenarios`). In-tree mock e2e is bash. 273 is stale (Traefik v3.0.0, Pester on Ubuntu, old action majors). 333’s seven scenarios match the mock set except redis / tls-system-ca / scope-headers (those stay mock-only).

Pin images to this tree’s examples, not 333’s older Traefik tag: `traefik:v3.7.11`, `crowdsecurity/crowdsec:v1.7.8`. Mock binary pin is already `v3.7.11` in `tests/e2e/mock/lib/common.sh`.

Run the Docker suite **in GitHub Actions on this fork** (`make e2e`) in addition to mock. Caller asked for a PR that passes CI and for the real tests to be reviewed. 333 left Docker local-only for upstream; this ticket is this repo.

Keep mock CI. Do not delete `e2e_mock`. Do not port Pester. Do not change bouncer runtime Go.

This `origin/master` has **no** `openspec/` tree. Propose bootstraps `openspec/specs/domains.md` and a new `build_e2e_*` spec. Knowledge/devdocs is also absent here; usage packet for the Docker harness is produced when the files exist.

## Open questions

- Q: Which implementation to land — Pester 273, bash 333, or a hybrid?
  Decision: assumed — port bash Docker suite from `upstream/feat/e2e-docker` (PR 333) onto current `master`; do not port Pester 273.
  By: explore

- Q: Should GitHub Actions in this repo run the Docker suite, or keep it local-only like 333?
  Decision: assumed — run `make e2e` in CI on this fork (new or extended workflow) so the PR proves real-stack coverage; keep `make e2e_mock` as well.
  By: explore

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
