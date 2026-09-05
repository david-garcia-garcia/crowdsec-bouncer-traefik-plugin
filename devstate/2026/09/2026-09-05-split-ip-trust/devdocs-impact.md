# Devdocs impact
change: split-ip-checker-network

## Units
- Trusted-IP lookup — subsystem — `pkg/ip` (`checker.go` hop-trust, `network.go` InNetwork)
- GetRemoteIP — pattern — client-address owner on every ServeHTTP

## Findings
- [x] language-gap  GetRemoteIP — `core_plugin_ip.md` had How-to/Overview mention, no Language term
- [x] stale-usage  Trusted-IP lookup — How-to did not say to call GetRemoteIP then Contains; Key files already listed checker.go/network.go from implement
