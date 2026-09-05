# Dragonfly Redis protocol compatibility

Dragonfly is an in-memory datastore that speaks Redis RESP (and HTTP) on the same TCP port. Official docs present it as Redis-API compatible with no client code changes. This finding covers the commands a tiny GET/SET/DEL/MGET client uses, the Docker image to run as an e2e stand-in, and documented gaps.

## Image and tag

Canonical image on official Docker and Compose docs: `docker.dragonflydb.io/dragonflydb/dragonfly` (untagged pull = latest).

Owners: [Install with Docker](https://www.dragonflydb.io/docs/getting-started/docker); [Install with Docker Compose](https://www.dragonflydb.io/docs/getting-started/docker-compose); `github.com/dragonflydb/dragonfly@e94300e6990093ec093cfb00d60c2e77ea4907e4:contrib/docker/docker-compose.yml`. Extracts: `.sources/docker.md`, `.sources/docker-compose.md`, `.sources/docker-compose.yml.md`.

Maintainer (romange) on a vendor GitHub discussion: image tags correspond to Dragonfly releases, e.g. `docker.dragonflydb.io/dragonflydb/dragonfly:v1.19.0`; untagged pulls latest.

Owner: [Discussion #3233](https://github.com/dragonflydb/dragonfly/discussions/3233) (`authority: vendor`). Extract: `.sources/discussion-3233.md`.

Latest GitHub release on 2026-09-03 is **v1.40.2** (commit `e94300e6990093ec093cfb00d60c2e77ea4907e4`). Command-compatibility table on the docs site was verified against **Dragonfly v1.40.0**.

Owners: [GitHub release v1.40.2](https://github.com/dragonflydb/dragonfly/releases/tag/v1.40.2); [API Compatibility](https://www.dragonflydb.io/docs/command-reference/compatibility). Extracts: `.sources/release-v1.40.2.md`, `.sources/compatibility.md`.

**Recommend for e2e:** `docker.dragonflydb.io/dragonflydb/dragonfly:v1.40.2`. Pinning matches the current release and the v1.40.x compatibility matrix. Untagged `latest` tracks whatever the registry serves next.

Docker Hub `docker.io/dragonflydb/dragonfly` exists but its listed tag is `v1.27.1`, last updated over a year before this fetch. The Hub page’s own start command still points at `docker.dragonflydb.io/dragonflydb/dragonfly`. Do not use the Hub `v1.27.1` pin as a current Redis stand-in.

Owner: [hub.docker.com/r/dragonflydb/dragonfly](https://hub.docker.com/r/dragonflydb/dragonfly). Extract: `.sources/hub-docker.md`.

Windows/macOS run from official Docker docs (port map, memlock):

`docker run -p 6379:6379 --ulimit memlock=-1 docker.dragonflydb.io/dragonflydb/dragonfly`

Official Compose maps `6379:6379` and sets `ulimits.memlock: -1`.

## Port, AUTH, SELECT

`--port` default **6379**. `--requirepass` default empty (AUTH optional). `--dbnum` default **16**. `SELECT` is fully supported; new connections use database 0. `AUTH [username] password` is fully supported; omitting username uses ACL user `default`.

Owners: [Server Configuration Flags](https://www.dragonflydb.io/docs/managing-dragonfly/flags); [v1.40.2 README Configuration](https://github.com/dragonflydb/dragonfly/blob/e94300e6990093ec093cfb00d60c2e77ea4907e4/README.md); [AUTH](https://www.dragonflydb.io/docs/command-reference/server-management/auth); [SELECT](https://www.dragonflydb.io/docs/command-reference/server-management/select); compatibility table. Extracts: `.sources/flags.md`, `.sources/README.md`, `.sources/auth.md`, `.sources/select.md`, `.sources/compatibility.md`.

Install/Docker docs: out of the box the process answers both HTTP and RESP on that port; `redis-cli -p 6379` then `SET`/`GET` works. The server picks the protocol at connection start.

Owners: [Install](https://www.dragonflydb.io/install); [Install with Docker](https://www.dragonflydb.io/docs/getting-started/docker); README “Native HTTP console”. Extracts: `.sources/install.md`, `.sources/docker.md`, `.sources/README.md`.

## Commands a tiny GET/SET/DEL/MGET client needs

Compatibility table (verified Dragonfly v1.40.0 vs Redis 8.6.4): “Fully supported” means the command and documented options/subcommands are accepted. It **does not** mean byte-for-byte identical behaviour.

| Command | Table | Notes from the command page |
| --- | --- | --- |
| GET | Fully supported | Missing key → `nil`. Strings are binary-safe. |
| MGET | Fully supported | One array slot per key; missing → `nil`, not an error. |
| DEL | Fully supported | Integer count of removed keys; missing keys ignored. |
| SET | Partially supported | Missing Redis-8 conditionals **IFDEQ, IFDNE, IFEQ, IFNE**. Syntax includes `EX seconds` / `PX` / `EXAT` / `PXAT` / `KEEPTTL` / `NX` / `XX` / `GET`. `SET key value EX 10` is documented and used in examples. |
| SETEX | Fully supported | |
| AUTH | Fully supported | |
| SELECT | Fully supported | |
| TTL | Fully supported | |

Owners: compatibility table plus [SET](https://www.dragonflydb.io/docs/command-reference/strings/set), [GET](https://www.dragonflydb.io/docs/command-reference/strings/get), [MGET](https://www.dragonflydb.io/docs/command-reference/strings/mget), [DEL](https://www.dragonflydb.io/docs/command-reference/generic/del). Extracts: `.sources/compatibility.md`, `.sources/set.md`, `.sources/get.md`, `.sources/mget.md`, `.sources/del.md`.

A client that sends RESP `SET name data EX <seconds>` (as SimpleRedis PR #8 does) uses an option the SET page documents. The table’s SET gaps are other conditionals, not `EX`.

## Protocol gaps vs Redis for that tiny client

Nothing in the official compatibility table marks GET, MGET, DEL, AUTH, SELECT, TTL, or SETEX as missing or partial. SET is partial only for IFDEQ/IFDNE/IFEQ/IFNE, which that client does not send.

Documented differences that do **not** apply to `SET … EX <integer seconds>` / GET / DEL / MGET:

- Millisecond expiry rounding for PEXPIRE-class deadlines **greater than 2^28 ms** (README). Relative `EX` seconds used by a tiny SET client is outside that clause.
- `SWAPDB` unsupported; cluster slot-assignment commands mostly unsupported. A single-node cache e2e does not need them.
- HTTP on port 6379 is auto-detected at connect. A client that writes RESP arrays is using the Redis protocol path, not HTTP.

Owners: compatibility table; README “Expiration deadlines with relative accuracy” and HTTP console; SET page. Inference that a RESP-only GET/SET/DEL/MGET client is unaffected by HTTP-on-same-port: those files (protocol auto-detect + RESP command support). Extracts: `.sources/compatibility.md`, `.sources/README.md`, `.sources/set.md`.

## Reasonable e2e stand-in for Redis?

Yes, for a client limited to RESP GET/SET (with EX)/DEL/MGET plus optional AUTH and SELECT: official install and Docker docs demonstrate `redis-cli` SET/GET on 6379; those commands are fully supported (SET’s only table gaps are unused conditionals); default port and `dbnum` 16 match Redis-like SELECT. Pin `docker.dragonflydb.io/dragonflydb/dragonfly:v1.40.2`, map 6379, set `ulimit memlock=-1`. Do not treat “fully supported” as a promise of byte-identical replies on every edge.

Owners: install/Docker docs; compatibility disclaimer; flags defaults. Inference on “reasonable stand-in”: those official pages plus the command table covering the client’s surface. Extracts listed above.
