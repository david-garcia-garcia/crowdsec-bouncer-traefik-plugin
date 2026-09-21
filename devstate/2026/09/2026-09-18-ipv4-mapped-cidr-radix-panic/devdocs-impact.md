# Devdocs impact
change: ipv4-mapped-cidr-radix-panic
pin: origin/master...HEAD (84a9045ca54f8fa88de38a61f78bb54f16dc0470) excluding `devstate/` and `.cursor/`

## Units
- Trusted-IP lookup — subsystem — `knowledge/devdocs/core_plugin_ip.md`, `pkg/ip`, `pkg/iplookup`
- IP lookup helper — pattern — `pkg/iplookup`, spec `core_plugin_ip_radix-lookup`
- Range membership — subsystem — `knowledge/devdocs/core_plugin_decisionscope.md`
- IPv4-mapped CIDR — pattern — spec `core_plugin_ip_radix-lookup` / `pkg/iplookup` insert

## Findings
- [x] language-gap  IPv4-mapped CIDR — `core_plugin_ip.md` has How-to, no Language term
