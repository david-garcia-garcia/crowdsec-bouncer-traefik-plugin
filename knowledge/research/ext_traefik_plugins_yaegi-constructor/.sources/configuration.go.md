---
url: https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/blob/99fb8b11e567b4d6d25e242b333373f2e078713e/pkg/configuration/configuration.go
title: pkg/configuration/configuration.go
fetched: 2026-09-05
authority: source
ref: this-repo@99fb8b11e567b4d6d25e242b333373f2e078713e:pkg/configuration/configuration.go
---

package configuration.
type Config struct { Enabled, LogLevel, CrowdsecMode, ... json tags }.
func New() *Config — this plugin's default-config helper, not Traefik's plugin New.
CreateConfig in bouncer.go returns configuration.New().
