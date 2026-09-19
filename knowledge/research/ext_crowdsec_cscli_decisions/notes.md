# cscli decisions

`cscli decisions add --ip` and `cscli decisions delete --ip` write remediations into a real LAPI. That is the injection path for a Docker Traefik + real Crowdsec suite. The mock e2e suite does not use these commands; it drives a fake LAPI over `/admin`.

Pinned engine for this tree: Crowdsec `v1.7.8`. Image: `crowdsecurity/crowdsec:v1.7.8`.

## Add

`cscli decisions add --ip <ip>` (alias `-i`) adds a decision on that IP to LAPI. Defaults: duration `4h`, type `ban`. Duration is `-d` / `--duration` (`1h`, `4h`, `30m`). Type is `-t` / `--type` (`ban`, `captcha`, `throttle`). Origin of a manual add is `cscli`.

Owners: [cscli decisions add (v1.7)](https://docs.crowdsec.net/docs/v1.7/cscli/cscli_decisions_add); [Decisions user guide](https://docs.crowdsec.net/u/user_guides/decisions_mgmt/). Extracts: `.sources/cscli_decisions_add.md`, `.sources/decisions_mgmt.md`.

v1.7.8 CLI source: `--duration` default `"4h"`, `--type` default `"ban"`, `--ip` sets scope `Ip`. Owner: `github.com/crowdsecurity/crowdsec@632274597a88a6b01ed41c0e6affca0f87ff26df:cmd/crowdsec-cli/clidecision/decisions.go`. Extract: `.sources/decisions.go.md`.

This tree’s examples inject via `docker exec crowdsec cscli decisions add --ip …` (ban, captcha, duration). Owner: `this-repo@ed4cb9beea83c2003d44ddb8fb9d1ac3d149ae87:README.md` and `examples/trusted-ips/README.md`. Extracts: `.sources/readme-manual-blocklist.md`, `.sources/trusted-ips-readme.md`.

## Delete

Official command is `cscli decisions delete --ip <ip>` (alias `-i`). That removes every active decision for the IP. Deleting by `--id` can leave other decisions on the same IP; `cscli decisions list` shows only the latest per IP. `--type` can restrict the delete. `--all` flushes all decisions, including community ones.

Owners: [cscli decisions delete (v1.7)](https://docs.crowdsec.net/docs/v1.7/cscli/cscli_decisions_delete); [Decisions user guide](https://docs.crowdsec.net/u/user_guides/decisions_mgmt/). Extracts: `.sources/cscli_decisions_delete.md`, `.sources/decisions_mgmt.md`.

In v1.7.8, `delete` has cobra alias `remove`, so `cscli decisions remove --ip` is the same command. Official docs document `delete`. This tree’s README uses `remove`; examples use `add` only.

Owners: `github.com/crowdsecurity/crowdsec@632274597a88a6b01ed41c0e6affca0f87ff26df:cmd/crowdsec-cli/clidecision/decisions.go` (`Aliases: []string{"remove"}`); `this-repo@ed4cb9beea83c2003d44ddb8fb9d1ac3d149ae87:README.md`. Extracts: `.sources/decisions.go.md`, `.sources/readme-manual-blocklist.md`.

## Docker exec

Inside the Crowdsec container, `cscli` is `/usr/local/bin/cscli`. The image wraps `cscli` with `-c "$CONFIG_FILE"` (default `/etc/crowdsec/config.yaml`). Tests talk to the container’s LAPI, not a mock.

Owner: `github.com/crowdsecurity/crowdsec@632274597a88a6b01ed41c0e6affca0f87ff26df:build/docker/README.md` (File Locations) and `build/docker/docker_start.sh` (`cscli()` wrapper). Extracts: `.sources/docker-readme.md`, `.sources/docker_start.sh.md`.
