# Devdocs impact
change: range-bare-ip-host-prefix

## Units
- Decision scopes — subsystem — `pkg/decisionscope` / Range index
- Trusted-IP lookup — subsystem — `pkg/ip` (`HostCIDR`)

## Findings
- [x] stale-usage  Trusted-IP lookup — How-to said convert a bare IP before `AddCIDR` but did not name the now-exported `HostCIDR` Range also calls
