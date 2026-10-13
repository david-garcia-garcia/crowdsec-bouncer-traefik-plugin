Retarget this tree's Traefik/Yaegi module identity from github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin to github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin so this fork is a second plugin that can load beside the upstream catalog plugin.

Must change:
- go.mod `module` line
- every Go import of that module (pkg/..., plugin.go)
- .traefik.yml `import`
- CI GOPATH checkout / working-directory under go/src/<module> (.github/workflows/*)
- examples, docker-compose, e2e: experimental.plugins.*.modulename, experimental.localplugins.*.modulename, bind-mounts plugins-local/src/<module>
- live OpenSpec / usage docs that SHALL load the old import
- yaegi_test / local-plugin paths if they hardcode the old GOPATH

Side-by-side:
- The Traefik static plugin *key* (experimental.plugins.bouncer) is operator-chosen and can collide if both plugins use the same key. For in-tree examples and e2e that only load THIS tree, changing modulename is enough; do not invent a second middleware family unless explore finds a collision inside this repo's compose. Document in README/usage that operators who keep upstream `plugins.bouncer` must register this fork under a different key (e.g. experimental.plugins.crowdsec) and use plugin.crowdsec in dynamic YAML.
- .traefik.yml displayName SHOULD distinguish from upstream (this is a different catalog entry).
- Do NOT try to publish to plugins.traefik.io from this PR. Catalog listing is out of tree.
- Do NOT change git remotes or GitHub repo name.
- Do NOT rewrite historical archive OpenSpec folders except live specs that still require the old import.
- Do NOT rename pkg/ directories.
- Do NOT retarget github.com/david-garcia-garcia/traefik-middleware-utilities or traefik-geoblock (already this org).

Bound: module/manifest/CI/example load-path identity only. No behavior change to ban/captcha/LAPI.

Human overrode chat-originated confirm: full unattended run. This is a second standalone Traefik plugin identity, breaking vs the upstream catalog plugin. Operators keep maxlerebourg loaded while they migrate.
