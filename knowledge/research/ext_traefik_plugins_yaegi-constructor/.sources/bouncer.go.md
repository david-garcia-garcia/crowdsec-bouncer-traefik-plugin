---
url: https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/blob/99fb8b11e567b4d6d25e242b333373f2e078713e/bouncer.go
title: bouncer.go
fetched: 2026-09-05
authority: source
ref: this-repo@99fb8b11e567b4d6d25e242b333373f2e078713e:bouncer.go
---

package crowdsec_bouncer_traefik_plugin.
Imports github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/{cache,captcha,configuration,ip,logger}.
CreateConfig() *configuration.Config — not *crowdsec_bouncer_traefik_plugin.Config.
New(_ context.Context, next http.Handler, config *configuration.Config, name string) (http.Handler, error).
Comment: traefik creates an instance of the bouncer per route; globals share state across those instances.
