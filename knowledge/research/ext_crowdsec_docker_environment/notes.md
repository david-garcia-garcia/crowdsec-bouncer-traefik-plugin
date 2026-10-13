# Docker environment variables

The `crowdsecurity/crowdsec` image registers bouncer API keys, installs hub collections, and optionally skips CAPI and the data-volume check from environment variables at container start. This tree pins `crowdsecurity/crowdsec:v1.7.8`.

## Bouncer key at start

Without TLS client auth, set `BOUNCER_KEY_<NAME>=<key>`. The image registers a bouncer named `<NAME>` with that key. Docker secrets named `bouncer_key_<name>` do the same. This path cannot update an existing bouncer; delete it first. Keys should be alphanumeric to avoid escaping issues.

Owner: [crowdsec `v1.7.8` Docker README — Automatic Bouncer Registration](https://github.com/crowdsecurity/crowdsec/blob/v1.7.8/build/docker/README.md). Same text is the Docker Hub image description. Extract: `.sources/docker-readme.md`. Official getting-started table: [Install with Docker](https://docs.crowdsec.net/u/getting_started/installation/docker). Extract: `.sources/install-docker.md`.

The v1.7.8 entrypoint loops `BOUNCER_KEY*` env vars, takes the name as everything after the second underscore (`cut -d_ -f3-`), and calls `cscli bouncers add "$NAME" -k "$KEY"` only if that name is not already listed.

Owner: `github.com/crowdsecurity/crowdsec@632274597a88a6b01ed41c0e6affca0f87ff26df:build/docker/docker_start.sh`. Extract: `.sources/docker_start.sh.md`.

This tree’s local compose sets `BOUNCER_KEY_TRAEFIK: 40796d93c2958f9e58345514e67740e5=` and the Traefik middleware `crowdseclapikey` to the same value. The root compose uses `BOUNCER_KEY_TRAEFIK: FIXME-LAPI-KEY-1=` with the same comment: one API key per bouncer. The tls-auth example uses `BOUNCER_KEY_TRAEFIK_FOO`, which the entrypoint registers as name `TRAEFIK_FOO`.

Owner: `this-repo@ed4cb9beea83c2003d44ddb8fb9d1ac3d149ae87:docker-compose.local.yml` and `docker-compose.yml`. Extracts: `.sources/docker-compose.local.yml.md`, `.sources/docker-compose.yml.md`.

## `COLLECTIONS`

Space-separated hub collections to install at start, e.g. `-e COLLECTIONS="crowdsecurity/linux crowdsecurity/apache2"`. The entrypoint runs `cscli collections install` for names in `COLLECTIONS` that are not also in `DISABLE_COLLECTIONS`, when the agent is not disabled.

Owners: [crowdsec `v1.7.8` Docker README env table](https://github.com/crowdsecurity/crowdsec/blob/v1.7.8/build/docker/README.md); `docker_start.sh` `prepare_hub`. Extracts: `.sources/docker-readme.md`, `.sources/docker_start.sh.md`.

This tree’s local and root compose set `COLLECTIONS: crowdsecurity/traefik crowdsecurity/appsec-virtual-patching crowdsecurity/appsec-generic-rules`. Owner: `this-repo@ed4cb9beea83c2003d44ddb8fb9d1ac3d149ae87:docker-compose.local.yml`. Extract: `.sources/docker-compose.local.yml.md`.

## `DISABLE_ONLINE_API`

Default false. When true, the entrypoint deletes `.api.server.online_client` from config and skips `cscli capi register`. Official description: disable online API registration for signal sharing.

Owners: Docker README env table; `docker_start.sh` (`istrue "$DISABLE_ONLINE_API"`). Extracts: `.sources/docker-readme.md`, `.sources/docker_start.sh.md`.

This tree’s tls-auth example sets `DISABLE_ONLINE_API: "true"`. The local/root compose files do not. Owner: `this-repo@ed4cb9beea83c2003d44ddb8fb9d1ac3d149ae87:examples/tls-auth/docker-compose.yml`. Extract: `.sources/tls-auth-docker-compose.yml.md`.

## `CROWDSEC_BYPASS_DB_VOLUME_CHECK`

Since CrowdSec 1.7.0, `/var/lib/crowdsec/data/` must be a volume or the container refuses to start. If that path is not a mount and `CROWDSEC_BYPASS_DB_VOLUME_CHECK` is unset, `docker_start.sh` prints the mandatory-volume message and `exit 0` (no restart loop). Set the variable to skip the check (log replay or remote DB on a LAPI-only container).

Owners: Docker README (Required configuration + developer env table); `docker_start.sh` volume check. Official getting-started page repeats the 1.7.0 volume requirement. Extracts: `.sources/docker-readme.md`, `.sources/docker_start.sh.md`, `.sources/install-docker.md`.

This tree’s compose files mount a named volume on `/var/lib/crowdsec/data/` and do not set the bypass. Owner: `this-repo@ed4cb9beea83c2003d44ddb8fb9d1ac3d149ae87:docker-compose.local.yml`. Extract: `.sources/docker-compose.local.yml.md`.
