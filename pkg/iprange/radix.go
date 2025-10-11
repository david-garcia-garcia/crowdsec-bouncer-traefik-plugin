package iprange

import (
	"net"

	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/types"
)

// RadixNode represents a node in the IP radix tree with generic data
type RadixNode struct {
	IsEndpoint bool        // true if this node represents the end of a CIDR block
	PrefixLen  int         // the prefix length of the CIDR block (if IsEndpoint is true)
	Data       interface{} // generic data associated with this CIDR block
	Left       *RadixNode  // for bit 0
	Right      *RadixNode  // for bit 1
}

// RadixTree provides fast O(log k) IP block lookups with generic data storage
type RadixTree struct {
	root *RadixNode
}

// NewRadixTree creates a new empty radix tree
func NewRadixTree() *RadixTree {
	return &RadixTree{
		root: &RadixNode{},
	}
}

// Insert adds a CIDR block with associated data to the radix tree
func (tree *RadixTree) Insert(cidr *net.IPNet, data interface{}) {
	ip := cidr.IP
	prefixLen, _ := cidr.Mask.Size()

	// Determine if this is IPv4 or IPv6 based on the original CIDR
	isIPv4 := ip.To4() != nil
	var bitStart int

	if isIPv4 {
		// For IPv4, convert to 16-byte representation
		ip = ip.To4().To16()
		bitStart = 96 // IPv4 starts at bit 96 in IPv4-mapped IPv6
	} else {
		// For IPv6, use as-is
		bitStart = 0
	}

	current := tree.root

	// Walk through each bit of the IP up to the prefix length
	for i := 0; i < prefixLen; i++ {
		// Calculate actual bit position in the 16-byte array
		actualBitPos := bitStart + i
		bytePos := actualBitPos / 8
		bitPos := 7 - (actualBitPos % 8) // Most significant bit first

		// Extract the bit (0 or 1)
		bit := (ip[bytePos] >> bitPos) & 1

		// Go left for 0, right for 1
		if bit == 0 {
			if current.Left == nil {
				current.Left = &RadixNode{}
			}
			current = current.Left
		} else {
			if current.Right == nil {
				current.Right = &RadixNode{}
			}
			current = current.Right
		}
	}

	// Mark this node as an endpoint with the prefix length and data
	current.IsEndpoint = true
	current.PrefixLen = prefixLen
	current.Data = data
}

// Remove removes a CIDR block from the radix tree
func (tree *RadixTree) Remove(cidr *net.IPNet) bool {
	ip := cidr.IP
	prefixLen, _ := cidr.Mask.Size()

	// Determine if this is IPv4 or IPv6
	isIPv4 := ip.To4() != nil
	var bitStart int

	if isIPv4 {
		ip = ip.To4().To16()
		bitStart = 96
	} else {
		bitStart = 0
	}

	// Track the path to the node for potential cleanup
	var path []*RadixNode
	var directions []int // 0 for left, 1 for right

	current := tree.root
	path = append(path, current)

	// Walk through each bit of the IP up to the prefix length
	for i := 0; i < prefixLen; i++ {
		actualBitPos := bitStart + i
		bytePos := actualBitPos / 8
		bitPos := 7 - (actualBitPos % 8)

		bit := (ip[bytePos] >> bitPos) & 1

		if bit == 0 {
			if current.Left == nil {
				return false // Path doesn't exist
			}
			current = current.Left
			directions = append(directions, 0)
		} else {
			if current.Right == nil {
				return false // Path doesn't exist
			}
			current = current.Right
			directions = append(directions, 1)
		}
		path = append(path, current)
	}

	// Check if this node is actually an endpoint with the expected prefix length
	if !current.IsEndpoint || current.PrefixLen != prefixLen {
		return false // Not found
	}

	// Remove the endpoint
	current.IsEndpoint = false
	current.Data = nil
	current.PrefixLen = 0

	// Clean up empty nodes from leaf to root
	tree.cleanup(path, directions)

	return true
}

// cleanup removes empty nodes that are no longer needed
func (tree *RadixTree) cleanup(path []*RadixNode, directions []int) {
	// Start from the leaf and work backwards
	for i := len(path) - 1; i > 0; i-- {
		current := path[i]
		parent := path[i-1]
		direction := directions[i-1]

		// If current node is empty (no endpoint, no children), remove it
		if !current.IsEndpoint && current.Left == nil && current.Right == nil {
			if direction == 0 {
				parent.Left = nil
			} else {
				parent.Right = nil
			}
		} else {
			// Stop cleanup if we encounter a non-empty node
			break
		}
	}
}

// Contains checks if an IP address is contained in any of the CIDR blocks in the tree
// Returns (found, data, prefixLength) where found indicates if a match was found
// Automatically handles expiration checking for types.DecisionData
func (tree *RadixTree) Contains(ip net.IP) (bool, interface{}, int) {
	if ip == nil {
		return false, nil, 0
	}

	// Determine if this is IPv4 or IPv6
	isIPv4 := ip.To4() != nil
	var bitStart, maxPrefixLen int

	if isIPv4 {
		ip = ip.To4().To16()
		bitStart = 96
		maxPrefixLen = 32 // IPv4 addresses have max 32-bit prefixes
	} else {
		bitStart = 0
		maxPrefixLen = 128 // IPv6 addresses have max 128-bit prefixes
	}

	current := tree.root
	var longestMatch interface{}
	longestPrefixLen := 0
	found := false

	// Walk through each bit of the IP
	for i := 0; i < maxPrefixLen && current != nil; i++ {
		// Check if current node is an endpoint (represents a CIDR block)
		if current.IsEndpoint && current.Data != nil {
			// Check if data is expired (if it's DecisionData)
			if decisionData, ok := current.Data.(*types.DecisionData); ok {
				if !decisionData.IsExpired() {
					found = true
					longestMatch = current.Data
					longestPrefixLen = current.PrefixLen
				}
				// Continue walking to find longest match even if this one is expired
			} else {
				// Non-expiring data
				found = true
				longestMatch = current.Data
				longestPrefixLen = current.PrefixLen
			}
		}

		// Calculate actual bit position in the 16-byte array
		actualBitPos := bitStart + i
		bytePos := actualBitPos / 8
		bitPos := 7 - (actualBitPos % 8)

		// Extract the bit (0 or 1)
		bit := (ip[bytePos] >> bitPos) & 1

		// Move to next node
		if bit == 0 {
			current = current.Left
		} else {
			current = current.Right
		}
	}

	// Check final node
	if current != nil && current.IsEndpoint && current.Data != nil {
		// Check if data is expired (if it's DecisionData)
		if decisionData, ok := current.Data.(*types.DecisionData); ok {
			if !decisionData.IsExpired() {
				found = true
				longestMatch = current.Data
				longestPrefixLen = current.PrefixLen
			}
		} else {
			// Non-expiring data
			found = true
			longestMatch = current.Data
			longestPrefixLen = current.PrefixLen
		}
	}

	return found, longestMatch, longestPrefixLen
}

// CleanupExpired removes all expired DecisionData entries from the tree
// This method traverses the entire tree and removes expired entries
func (tree *RadixTree) CleanupExpired() int {
	removed := 0
	tree.cleanupExpiredRecursive(tree.root, &removed)
	return removed
}

// cleanupExpiredRecursive recursively traverses the tree and removes expired entries
func (tree *RadixTree) cleanupExpiredRecursive(node *RadixNode, removed *int) {
	if node == nil {
		return
	}

	// Check if this node has expired data
	if node.IsEndpoint && node.Data != nil {
		if decisionData, ok := node.Data.(*types.DecisionData); ok {
			if decisionData.IsExpired() {
				node.IsEndpoint = false
				node.Data = nil
				node.PrefixLen = 0
				*removed++
			}
		}
	}

	// Recursively clean children
	tree.cleanupExpiredRecursive(node.Left, removed)
	tree.cleanupExpiredRecursive(node.Right, removed)

	// Clean up empty nodes (no endpoint, no children)
	if !node.IsEndpoint && node.Left == nil && node.Right == nil && node != tree.root {
		// This node is empty and can be removed, but we need parent reference
		// For now, we'll leave empty nodes (they don't consume much memory)
		// A full cleanup would require parent tracking or tree rebuilding
	}
}
