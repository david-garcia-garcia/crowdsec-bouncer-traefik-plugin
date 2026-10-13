# IP lookup helper

Package `iplookup` in [david-garcia-garcia/traefik-geoblock](https://github.com/david-garcia-garcia/traefik-geoblock) (`master` HEAD `0c2f46dab0fd6cac90f4db0e4ac2c5d2a58325cf`, tag `v1.2.0`). Binary radix tree of CIDR membership: insert prefixes, then ask whether an IP is contained and which prefix length matched.

Owner: `github.com/david-garcia-garcia/traefik-geoblock@0c2f46dab0fd6cac90f4db0e4ac2c5d2a58325cf:pkg/iplookup/iplookup.go`. Extract: `.sources/iplookup.go.md`. Tests: `…@0c2f46da:pkg/iplookup/iplookup_test.go`. Extract: `.sources/iplookup_test.go.md`.

## Public API

Exported type `IpLookupHelper`. Unexported `ipRadixTree` / `radixNode`.

| Symbol | Signature | Behaviour |
| --- | --- | --- |
| `NewEmptyIpLookupHelper` | `() *IpLookupHelper` | Empty tree, `count` zero. |
| `AddCIDR` | `(cidr string) error` | `net.ParseCIDR`; on failure `parse error on CIDR %q: %v`; else insert and `count++`. |
| `NewIpLookupHelper` | `(cidrBlocks []string) (*IpLookupHelper, error)` | Empty helper, then `AddCIDR` each string; first error returns `nil, err`. |
| `IsContained` | `(ipAddr net.IP) (bool, int, error)` | Nil IP → `false, 0, "IP address is nil"`. Else tree `contains`: `(found, prefixLen, nil)`. |
| `Count` | `() int` | Number of successful `AddCIDR` calls (not unique prefixes). |

Owner: `…@0c2f46da:pkg/iplookup/iplookup.go`. Extract: `.sources/iplookup.go.md`.

Invalid CIDR strings (`invalid-cidr`, `192.168.1.0/33`, `2001:db8::/129`, missing prefix, empty string) make `NewIpLookupHelper` return an error. Owner: `…@0c2f46da:pkg/iplookup/iplookup_test.go` (`TestIpLookupHelper_InvalidCIDR`). Extract: `.sources/iplookup_test.go.md`.

## Tree shape

One binary trie (`left` = bit 0, `right` = bit 1). Every IP is a 16-byte array. IPv4 (`ip.To4() != nil`) is converted with `ip.To4().To16()` (IPv4-mapped form) and walked from **bitStart = 96**. IPv6 is used as-is from **bitStart = 0**. Mixed v4/v6 CIDRs live in that single tree.

Owner: `…@0c2f46da:pkg/iplookup/iplookup.go` (`insert`, `contains`). Extract: `.sources/iplookup.go.md`. Mixed-family cases: `TestIpLookupHelper_MixedIPv4AndIPv6`. Extract: `.sources/iplookup_test.go.md`.

`insert` with `prefixLen == 0` marks that shared `root` as an endpoint. `contains` starts both families at the same root, so `0.0.0.0/0` matches IPv6 and `::/0` matches IPv4. Owner: `…@0c2f46da:pkg/iplookup/iplookup.go` (`insert` after the bit walk, `contains` `current := tree.root`). This plugin’s `pkg/iplookup` keeps separate v4/v6 roots so membership matches `net.IPNet.Contains`.

Nodes store **boolean membership plus prefix length only** (`isEndpoint`, `prefixLen`). There is no associated value, payload, or decision object. `contains` / `IsContained` return whether any endpoint was hit and that endpoint’s `prefixLen`.

Owner: `…@0c2f46da:pkg/iplookup/iplookup.go` (`radixNode`, `contains`, `IsContained`). Extract: `.sources/iplookup.go.md`.

## Longest-prefix match

`contains` walks toward the address and, at every endpoint, records `found` and `longestMatch = current.prefixLen`, then continues. The last endpoint seen wins, so a more specific CIDR overrides a covering one (`192.168.1.10/32` over `192.168.1.0/24`; `2001:db8:85a3:8d3::/64` over `/48` over `/32`).

Owner: `…@0c2f46da:pkg/iplookup/iplookup.go` (`contains` comment: “Continue walking to find longest match”). Tests: `TestIpLookupHelper_IPv4`, `_IPv6`, `_OverlappingRanges`, `_PrefixLengthAccuracy`. Extracts: `.sources/iplookup.go.md`, `.sources/iplookup_test.go.md`.

## Insert and contains complexity

`insert` loops `i := 0; i < prefixLen` (one bit walk per prefix bit). `contains` loops `i := 0; i < maxPrefixLen` with `maxPrefixLen` **32** (IPv4) or **128** (IPv6), stopping early if `current == nil`. Type comment: lookups are `O(log k)` with `k` the IP bit length. Helper comment: `O(32)` IPv4 and `O(128)` IPv6 instead of `O(n)` linear search over CIDRs.

Owner: `…@0c2f46da:pkg/iplookup/iplookup.go` (`ipRadixTree` / `IpLookupHelper` comments, `insert`, `contains`). Extract: `.sources/iplookup.go.md`.

The loops are bounded by bit length, not by `count`. That they are independent of the number of stored CIDRs is inference from those loop bounds (`authority: inference`).
