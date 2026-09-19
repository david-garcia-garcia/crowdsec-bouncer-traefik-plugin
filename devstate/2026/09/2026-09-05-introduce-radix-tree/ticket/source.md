# introduce-radix-tree

Use a radix tree implementation to speed up IP-range lookups in several places, including `pkg/ip/ip.go` and RANGE REMEDIATION behaviour.

Reusable component (copy/adapt): https://github.com/david-garcia-garcia/traefik-geoblock/blob/master/pkg/iplookup/iplookup.go
Tests: https://github.com/david-garcia-garcia/traefik-geoblock/blob/master/pkg/iplookup/iplookup_test.go

For range remediation, do NOT integrate the radix tree in this change. That is a future ticket.

Dedicated worktree. PR against `master`.
