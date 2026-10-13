---
url: https://github.com/traefik/plugindemo/blob/01ec61f2084a7386143310735eb48eb3e990bd19/demo.go
title: plugindemo/demo.go
fetched: 2026-09-05
authority: source
ref: github.com/traefik/plugindemo@01ec61f2084a7386143310735eb48eb3e990bd19:demo.go
---

package plugindemo (module github.com/traefik/plugindemo).
type Config struct { Headers map[string]string }.
CreateConfig() *Config.
New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error).
Single root package; Config is named Config in that package.
