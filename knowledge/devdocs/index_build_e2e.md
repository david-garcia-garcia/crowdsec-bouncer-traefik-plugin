# build / e2e

## Mock LAPI e2e
priority: normal
local: build_e2e_mock.md
description: Binary Traefik plus mocklapi scenarios, including two bouncers in one process.

## Real-stack e2e
priority: normal
local: build_e2e_real.md
description: Docker Traefik + Crowdsec Pester suite, separate from the mock LAPI suite.

## Go-layer real Redis e2e
priority: normal
local: build_e2e_go-redis.md
description: Tagged go test against Dragonfly, not Traefik HTTP and not the in-process RESP stand-in.
