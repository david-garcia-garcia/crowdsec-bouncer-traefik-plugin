// Package iplookup stores CIDR prefixes in a binary radix tree and answers
// whether an IP is contained. Adapted from
// github.com/david-garcia-garcia/traefik-geoblock@0c2f46da pkg/iplookup.
package iplookup

import (
	"fmt"
	"net"
)

// radixNode is one bit of a CIDR walk. left is bit 0, right is bit 1.
type radixNode struct {
	isEndpoint bool       // true if this node is the end of a stored CIDR
	prefixLen  int        // prefix length when isEndpoint is true
	left       *radixNode // bit 0
	right      *radixNode // bit 1
}

// ipRadixTree is a binary trie of IPv4 and IPv6 CIDRs in one 16-byte bit space.
type ipRadixTree struct {
	root *radixNode
}

// newIPRadixTree returns an empty tree.
func newIPRadixTree() *ipRadixTree {
	return &ipRadixTree{
		root: &radixNode{},
	}
}

// insert stores one CIDR. IPv4 is walked from bit 96 of the IPv4-mapped form.
func (tree *ipRadixTree) insert(cidr *net.IPNet) {
	ip := cidr.IP
	prefixLen, _ := cidr.Mask.Size()

	isIPv4 := ip.To4() != nil
	var bitStart int

	// IPv4 lives in the last 32 bits of the 16-byte IPv4-mapped form.
	if isIPv4 {
		ip = ip.To4().To16()
		bitStart = 96
	} else {
		bitStart = 0
	}

	current := tree.root

	// Walk prefix bits, creating missing children.
	for i := 0; i < prefixLen; i++ {
		actualBitPos := bitStart + i
		bytePos := actualBitPos / 8
		bitPos := 7 - (actualBitPos % 8)

		bit := (ip[bytePos] >> bitPos) & 1

		if bit == 0 {
			if current.left == nil {
				current.left = &radixNode{}
			}
			current = current.left
		} else {
			if current.right == nil {
				current.right = &radixNode{}
			}
			current = current.right
		}
	}

	current.isEndpoint = true
	current.prefixLen = prefixLen
}

// contains reports whether ip sits in any stored CIDR and the longest matching prefix.
func (tree *ipRadixTree) contains(ip net.IP) (bool, int) {
	isIPv4 := ip.To4() != nil
	var bitStart, maxPrefixLen int

	// IPv4 is mapped the same way as insert (bit 96, 32-bit walk).
	if isIPv4 {
		ip = ip.To4().To16()
		bitStart = 96
		maxPrefixLen = 32
	} else {
		bitStart = 0
		maxPrefixLen = 128
	}

	current := tree.root
	longestMatch := 0
	found := false

	// Record each endpoint on the path so the last (longest) prefix wins.
	for i := 0; i < maxPrefixLen && current != nil; i++ {
		if current.isEndpoint {
			found = true
			longestMatch = current.prefixLen
		}

		actualBitPos := bitStart + i
		bytePos := actualBitPos / 8
		bitPos := 7 - (actualBitPos % 8)

		bit := (ip[bytePos] >> bitPos) & 1

		if bit == 0 {
			current = current.left
		} else {
			current = current.right
		}
	}

	// The last bit can land on an endpoint after the loop.
	if current != nil && current.isEndpoint {
		found = true
		longestMatch = current.prefixLen
	}

	return found, longestMatch
}

// Helper is a CIDR set with prefix-bounded membership lookup.
type Helper struct {
	tree  *ipRadixTree
	count int
}

// NewEmptyHelper returns a Helper with no CIDRs.
func NewEmptyHelper() *Helper {
	return &Helper{
		tree: newIPRadixTree(),
	}
}

// AddCIDR parses cidr and inserts it. Duplicate inserts still increment Count.
func (helper *Helper) AddCIDR(cidr string) error {
	_, block, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("parse error on CIDR %q: %w", cidr, err)
	}
	helper.tree.insert(block)
	helper.count++
	return nil
}

// Count returns how many successful AddCIDR calls have been made.
func (helper *Helper) Count() int {
	return helper.count
}

// NewHelper builds a Helper from cidrBlocks. The first parse error fails the whole set.
func NewHelper(cidrBlocks []string) (*Helper, error) {
	helper := NewEmptyHelper()

	for _, cidr := range cidrBlocks {
		if err := helper.AddCIDR(cidr); err != nil {
			return nil, err
		}
	}

	return helper, nil
}

// IsContained reports whether ipAddr is inside any stored CIDR.
// The int is the longest matching prefix length (0 when not found).
func (helper *Helper) IsContained(ipAddr net.IP) (bool, int, error) {
	if ipAddr == nil {
		return false, 0, fmt.Errorf("IP address is nil")
	}
	found, prefixLen := helper.tree.contains(ipAddr)
	return found, prefixLen, nil
}
