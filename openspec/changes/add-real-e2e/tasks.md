## 1. Checkout path for Yaegi on this fork

- [ ] 1.1 In `.github/workflows/main.yml`, set the checkout `path` to `go/src/github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin` (the `go.mod` module path), not `github.com/${{ github.repository }}`

## 2. Docker e2e harness from upstream PR 333

- [ ] 2.1 Copy `tests/e2e/lib/common.sh` and `tests/e2e/README.md` from `upstream/feat/e2e-docker`
- [ ] 2.2 Copy all seven scenario directories from `upstream/feat/e2e-docker` into `tests/e2e/scenarios/` (`stream-mode`, `live-mode`, `none-mode`, `trusted-ips`, `custom-ban-page`, `captcha`, `appsec`)
- [ ] 2.3 Pin every scenario compose Traefik image to `traefik:v3.7.11`; keep Crowdsec `crowdsecurity/crowdsec:v1.7.8`
- [ ] 2.4 Add `make e2e` and `make e2e_%` next to existing `e2e_mock` targets; discover scenarios from `tests/e2e/scenarios/*`

## 3. CI and docs

- [ ] 3.1 Add a GitHub Actions job that runs `make e2e` on pull requests; keep the mock `make e2e_mock` job
- [ ] 3.2 Update `tests/e2e/mock/README.md` and Makefile comments so they no longer say the Docker suite lives only in another PR
- [ ] 3.3 Run existing local tests (`make` / `go test`); set `localTests` from the result
