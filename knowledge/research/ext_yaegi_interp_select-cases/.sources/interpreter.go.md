---
url: https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/deb8ebfe0f2aefa19b62102fd85878b4882dc42f/pkg/yaegitest/interpreter.go
title: pkg/yaegitest interpreter wrapper
fetched: 2026-09-26
authority: source
ref: this-repo@deb8ebfe0f2aefa19b62102fd85878b4882dc42f:pkg/yaegitest/interpreter.go
---

Package comment: runs a program under the yaegi v0.16.1 binary the way Traefik loads this module (GOPATH/src plus vendored middleware utilities). The binary is not a module dependency; CI installs it. GoPath comment: Yaegi v0.16 resolves imports from GOPATH/src, the same way Traefik loads the plugin.
