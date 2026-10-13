---
url: https://github.com/traefik/traefik/blob/faa1eb590646aed94e561e24a59be0c47353ae95/Dockerfile
title: Traefik Dockerfile (v3.7.11)
fetched: 2026-09-05
authority: source
ref: github.com/traefik/traefik@faa1eb590646aed94e561e24a59be0c47353ae95:Dockerfile
---

FROM alpine:3.24
COPY ./dist/$TARGETPLATFORM/traefik /
ENTRYPOINT ["/traefik"]
No WORKDIR instruction.
Inference (not stated here): Docker default working directory is /, so ./plugins-local is /plugins-local in this image.
