---
url: https://doc.traefik.io/traefik-hub/api-gateway/guides/plugin-development-guide
title: Plugin Development Guide (Traefik Hub) — Local Plugin Development
fetched: 2026-09-05
authority: official
---

Docker Compose: set experimental.localPlugins.myPlugin.moduleName to github.com/my-org/my-plugin.
Mount the host plugin directory to /plugins-local/src/github.com/my-org/my-plugin.
Kubernetes Helm: additionalVolumeMounts mountPath /plugins-local/src/github.com/my-org/my-plugin.
k3d: --volume "$(pwd)/my-plugin:/plugins-local/src/github.com/my-org/my-plugin@server:0"
Plugin directory on the host needs plugin.go, go.mod, .traefik.yml.
