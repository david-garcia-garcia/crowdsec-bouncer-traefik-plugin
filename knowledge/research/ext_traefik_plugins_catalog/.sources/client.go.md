---
url: https://github.com/traefik/traefik/blob/f6b7940b761abe0d16ee4b03588a0318481d86d8/pkg/plugins/client.go
title: pkg/plugins/client.go
fetched: 2026-09-18
authority: source
ref: github.com/traefik/traefik@f6b7940b761abe0d16ee4b03588a0318481d86d8:pkg/plugins/client.go
---

const pluginsURL = "https://plugins.traefik.io/public/" (same string as v3.7.11 manager.go).
Download: GET path.Join(baseURL.Path, "download", pName, pVersion).
Status 200 writes the archive; 304 reuses cache; any other status returns "error: %d: %s".
Check: GET .../validate/{pName}/{pVersion}.
This helper lived on Client in this later commit; v3.7.11 calls the same catalog via Manager.downloader.
