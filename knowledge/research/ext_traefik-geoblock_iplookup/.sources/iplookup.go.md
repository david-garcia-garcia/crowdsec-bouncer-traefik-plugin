---
url: https://github.com/david-garcia-garcia/traefik-geoblock/blob/0c2f46dab0fd6cac90f4db0e4ac2c5d2a58325cf/pkg/iplookup/iplookup.go
title: iplookup.go
fetched: 2026-09-05
authority: source
ref: github.com/david-garcia-garcia/traefik-geoblock@0c2f46dab0fd6cac90f4db0e4ac2c5d2a58325cf:pkg/iplookup/iplookup.go
---

Package iplookup. Unexported radixNode: isEndpoint bool, prefixLen int, left/right *radixNode (bit 0 / bit 1). No payload field.

Unexported ipRadixTree { root *radixNode }. Comment: fast O(log k) IP block lookups; k is IP bit length (32 IPv4, 128 IPv6). newIPRadixTree: root is empty radixNode.

insert(cidr *net.IPNet): prefixLen from cidr.Mask.Size(). If ip.To4() != nil: ip = ip.To4().To16(), bitStart = 96. Else bitStart = 0. Walk prefixLen bits from bitStart in the 16-byte array (MSB first). Create left/right as needed. Mark current isEndpoint=true, prefixLen=prefixLen.

contains(ip net.IP) (bool, int): same v4/v6 split. IPv4: To4().To16(), bitStart=96, maxPrefixLen=32. IPv6: bitStart=0, maxPrefixLen=128. Walk up to maxPrefixLen while current != nil. At each endpoint: found=true, longestMatch=current.prefixLen; continue for longest match. After loop, check final node. Return found, longestMatch.

IpLookupHelper: tree *ipRadixTree, count int. Comment: O(32) IPv4 and O(128) IPv6 lookups instead of O(n) linear search.

NewEmptyIpLookupHelper() *IpLookupHelper: empty tree.

AddCIDR(cidr string) error: net.ParseCIDR; on err return fmt.Errorf("parse error on CIDR %q: %v", cidr, err); else insert and count++.

Count() int: return count.

NewIpLookupHelper(cidrBlocks []string) (*IpLookupHelper, error): NewEmptyIpLookupHelper then AddCIDR each; first error returns nil, err.

IsContained(ipAddr net.IP) (bool, int, error): nil IP → false, 0, fmt.Errorf("IP address is nil"); else tree.contains.
