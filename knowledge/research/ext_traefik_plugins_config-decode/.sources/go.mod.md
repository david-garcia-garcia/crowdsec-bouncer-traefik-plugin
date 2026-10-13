---
url: https://github.com/traefik/traefik/blob/faa1eb590646aed94e561e24a59be0c47353ae95/go.mod
title: Traefik v3.7.11 go.mod mapstructure pin
fetched: 2026-09-18
authority: source
ref: github.com/traefik/traefik@faa1eb590646aed94e561e24a59be0c47353ae95:go.mod
---

Direct: github.com/mitchellh/mapstructure v1.5.1-0.20231216201459-8508981c8b6c // No tag on the repo.

Indirect: github.com/go-viper/mapstructure/v2 v2.5.0.

createConfig imports github.com/mitchellh/mapstructure (middlewareyaegi.go), not the viper v2 module.
