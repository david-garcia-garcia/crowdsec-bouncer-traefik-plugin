# Specs
change: store-range-remediation-on-radix
- fold core_plugin_ip_radix-lookup (Range helper endpoint MAY store remediation; Checker stays boolean)
- fold core_plugin_decisions_scopes (Range hit returns stored string from winning prefix; MUST NOT re-parse CIDRs)
