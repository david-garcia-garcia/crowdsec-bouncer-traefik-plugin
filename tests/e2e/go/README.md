# Go-layer real Redis (Dragonfly)

`go test` files with `//go:build realredis` talk to a live Redis-protocol server.
They do not use the in-process RESP stand-in in `pkg/decisionstore/zzz_testredis_test.go`.

Dragonfly is the same image as the Pester stack (`docker.dragonflydb.io/dragonflydb/dragonfly:v1.40.2`).
This compose file publishes `6379` so the Go process on the host can dial it. Traefik and Crowdsec stay down.

```bash
make test_realredis
# or
docker compose -f tests/e2e/go/docker-compose.yml up -d
go test -tags realredis -count=1 ./pkg/decisionstore
```

Override the address with `REALREDIS_ADDR` (default `127.0.0.1:6379`).

`make test` does not set `-tags realredis`, so ordinary unit tests stay docker-free.
