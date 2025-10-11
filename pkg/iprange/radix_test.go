package iprange

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/types"
)

func TestRadixTree_BasicOperations(t *testing.T) {
	tree := NewRadixTree()

	// Test inserting IPv4 CIDR
	_, cidr1, _ := net.ParseCIDR("192.168.1.0/24")
	data1 := "test-data-1"
	tree.Insert(cidr1, data1)

	// Test contains for IP in range
	ip1 := net.ParseIP("192.168.1.100")
	found, data, prefixLen := tree.Contains(ip1)
	if !found {
		t.Error("Expected IP 192.168.1.100 to be found in 192.168.1.0/24")
	}
	if data != data1 {
		t.Errorf("Expected data '%s', got '%v'", data1, data)
	}
	if prefixLen != 24 {
		t.Errorf("Expected prefix length 24, got %d", prefixLen)
	}

	// Test IP outside range
	ip2 := net.ParseIP("192.168.2.100")
	found, _, _ = tree.Contains(ip2)
	if found {
		t.Error("Expected IP 192.168.2.100 to not be found")
	}

	// Test removing the CIDR
	removed := tree.Remove(cidr1)
	if !removed {
		t.Error("Expected CIDR to be removed successfully")
	}

	// Verify it's no longer found
	found, _, _ = tree.Contains(ip1)
	if found {
		t.Error("Expected IP to not be found after CIDR removal")
	}
}

func TestRadixTree_IPv6(t *testing.T) {
	tree := NewRadixTree()

	// Test inserting IPv6 CIDR
	_, cidr, _ := net.ParseCIDR("2001:db8::/32")
	data := "ipv6-test-data"
	tree.Insert(cidr, data)

	// Test contains for IPv6 IP in range
	ip := net.ParseIP("2001:db8:1234:5678::1")
	found, retrievedData, prefixLen := tree.Contains(ip)
	if !found {
		t.Error("Expected IPv6 IP to be found in range")
	}
	if retrievedData != data {
		t.Errorf("Expected data '%s', got '%v'", data, retrievedData)
	}
	if prefixLen != 32 {
		t.Errorf("Expected prefix length 32, got %d", prefixLen)
	}

	// Test IPv6 IP outside range
	ip2 := net.ParseIP("2001:db9::1")
	found, _, _ = tree.Contains(ip2)
	if found {
		t.Error("Expected IPv6 IP outside range to not be found")
	}
}

func TestRadixTree_OverlappingRanges(t *testing.T) {
	tree := NewRadixTree()

	// Insert overlapping ranges
	_, cidr1, _ := net.ParseCIDR("192.168.0.0/16")  // Large network
	_, cidr2, _ := net.ParseCIDR("192.168.1.0/24")  // Subnet
	_, cidr3, _ := net.ParseCIDR("192.168.1.10/32") // Single IP

	tree.Insert(cidr1, "large-network")
	tree.Insert(cidr2, "subnet")
	tree.Insert(cidr3, "single-ip")

	tests := []struct {
		ip           string
		expectedData string
		expectedLen  int
	}{
		{"192.168.1.10", "single-ip", 32},     // Most specific
		{"192.168.1.50", "subnet", 24},        // Subnet match
		{"192.168.2.10", "large-network", 16}, // Large network match
	}

	for _, tt := range tests {
		ip := net.ParseIP(tt.ip)
		found, data, prefixLen := tree.Contains(ip)
		if !found {
			t.Errorf("Expected IP %s to be found", tt.ip)
			continue
		}
		if data != tt.expectedData {
			t.Errorf("IP %s: expected data '%s', got '%v'", tt.ip, tt.expectedData, data)
		}
		if prefixLen != tt.expectedLen {
			t.Errorf("IP %s: expected prefix length %d, got %d", tt.ip, tt.expectedLen, prefixLen)
		}
	}
}

func TestRadixTree_RemoveWithCleanup(t *testing.T) {
	tree := NewRadixTree()

	// Insert a CIDR
	_, cidr, _ := net.ParseCIDR("10.0.0.0/8")
	tree.Insert(cidr, "test-data")

	// Verify it's there
	ip := net.ParseIP("10.1.2.3")
	found, _, _ := tree.Contains(ip)
	if !found {
		t.Error("Expected IP to be found before removal")
	}

	// Remove it
	removed := tree.Remove(cidr)
	if !removed {
		t.Error("Expected CIDR to be removed")
	}

	// Verify it's gone
	found, _, _ = tree.Contains(ip)
	if found {
		t.Error("Expected IP to not be found after removal")
	}

	// Try to remove again (should return false)
	removed = tree.Remove(cidr)
	if removed {
		t.Error("Expected second removal to return false")
	}
}

func TestRadixTree_WithExpiration(t *testing.T) {
	tree := NewRadixTree()

	// Create decision data with expiration
	expiredData := &types.DecisionData{
		Type:      "ban",
		Source:    "test",
		Scenario:  "test-scenario",
		ExpiresAt: time.Now().Add(-1 * time.Hour), // Expired 1 hour ago
		Value:     "192.168.1.0/24",
	}

	validData := &types.DecisionData{
		Type:      "ban",
		Source:    "test",
		Scenario:  "test-scenario",
		ExpiresAt: time.Now().Add(1 * time.Hour), // Expires in 1 hour
		Value:     "10.0.0.0/8",
	}

	// Insert both
	_, expiredCidr, _ := net.ParseCIDR("192.168.1.0/24")
	_, validCidr, _ := net.ParseCIDR("10.0.0.0/8")
	tree.Insert(expiredCidr, expiredData)
	tree.Insert(validCidr, validData)

	// Check expired data - should not be found due to automatic expiration checking
	ip1 := net.ParseIP("192.168.1.100")
	found, _, _ := tree.Contains(ip1)
	if found {
		t.Error("Expected expired decision to not be found")
	}

	// Check valid data - should be found
	ip2 := net.ParseIP("10.1.2.3")
	found, data, prefixLen := tree.Contains(ip2)
	if !found {
		t.Error("Expected valid decision to be found")
	}
	if data != validData {
		t.Error("Expected to get valid data back")
	}
	if prefixLen != 8 {
		t.Errorf("Expected prefix length 8, got %d", prefixLen)
	}
}

func TestRadixTree_CleanupExpired(t *testing.T) {
	tree := NewRadixTree()

	// Create mixed expired and valid data
	expiredData1 := &types.DecisionData{
		Type:      "ban",
		Source:    "test",
		Scenario:  "expired-1",
		ExpiresAt: time.Now().Add(-1 * time.Hour),
		Value:     "192.168.1.0/24",
	}

	expiredData2 := &types.DecisionData{
		Type:      "ban",
		Source:    "test",
		Scenario:  "expired-2",
		ExpiresAt: time.Now().Add(-30 * time.Minute),
		Value:     "10.0.0.0/8",
	}

	validData := &types.DecisionData{
		Type:      "ban",
		Source:    "test",
		Scenario:  "valid",
		ExpiresAt: time.Now().Add(1 * time.Hour),
		Value:     "172.16.0.0/12",
	}

	// Insert all data
	_, expiredCidr1, _ := net.ParseCIDR("192.168.1.0/24")
	_, expiredCidr2, _ := net.ParseCIDR("10.0.0.0/8")
	_, validCidr, _ := net.ParseCIDR("172.16.0.0/12")

	tree.Insert(expiredCidr1, expiredData1)
	tree.Insert(expiredCidr2, expiredData2)
	tree.Insert(validCidr, validData)

	// Verify expired data is not found (automatic expiration in Contains)
	ip1 := net.ParseIP("192.168.1.100")
	found, _, _ := tree.Contains(ip1)
	if found {
		t.Error("Expected expired data to not be found")
	}

	ip2 := net.ParseIP("10.1.2.3")
	found, _, _ = tree.Contains(ip2)
	if found {
		t.Error("Expected expired data to not be found")
	}

	// Verify valid data is still found
	ip3 := net.ParseIP("172.16.1.1")
	found, data, _ := tree.Contains(ip3)
	if !found {
		t.Error("Expected valid data to be found")
	}
	if data != validData {
		t.Error("Expected to get valid data back")
	}

	// Test cleanup method
	removedCount := tree.CleanupExpired()
	if removedCount != 2 {
		t.Errorf("Expected 2 expired entries to be removed, got %d", removedCount)
	}

	// After cleanup, valid data should still be found
	found, data, _ = tree.Contains(ip3)
	if !found {
		t.Error("Expected valid data to still be found after cleanup")
	}
	if data != validData {
		t.Error("Expected to get valid data back after cleanup")
	}
}

func TestRadixTree_ExpiredNestedNodes(t *testing.T) {
	tree := NewRadixTree()

	// Create nested IP ranges with one expired in the middle
	// Structure: 10.0.0.0/8 > 10.1.0.0/16 (EXPIRED) > 10.1.1.0/24

	// Outermost range (valid)
	outerData := &types.DecisionData{
		Type:      "ban",
		Source:    "crowdsec",
		Scenario:  "outer-range",
		ExpiresAt: time.Now().Add(1 * time.Hour), // Valid for 1 hour
		Value:     "10.0.0.0/8",
	}

	// Middle range (EXPIRED) - this should be inserted but ignored
	expiredMiddleData := &types.DecisionData{
		Type:      "captcha",
		Source:    "crowdsec",
		Scenario:  "expired-middle",
		ExpiresAt: time.Now().Add(-1 * time.Hour), // Expired 1 hour ago
		Value:     "10.1.0.0/16",
	}

	// Innermost range (valid)
	innerData := &types.DecisionData{
		Type:      "ban",
		Source:    "crowdsec",
		Scenario:  "inner-range",
		ExpiresAt: time.Now().Add(2 * time.Hour), // Valid for 2 hours
		Value:     "10.1.1.0/24",
	}

	// Insert all ranges (including the expired one)
	_, outerCidr, _ := net.ParseCIDR("10.0.0.0/8")
	_, expiredMiddleCidr, _ := net.ParseCIDR("10.1.0.0/16")
	_, innerCidr, _ := net.ParseCIDR("10.1.1.0/24")

	tree.Insert(outerCidr, outerData)
	tree.Insert(expiredMiddleCidr, expiredMiddleData) // This is expired but should be inserted
	tree.Insert(innerCidr, innerData)

	// Test cases to validate expired node behavior
	tests := []struct {
		name         string
		ip           string
		shouldFind   bool
		expectedData *types.DecisionData
		expectedLen  int
		description  string
	}{
		{
			name:         "IP in innermost range",
			ip:           "10.1.1.50",
			shouldFind:   true,
			expectedData: innerData,
			expectedLen:  24,
			description:  "Should find most specific valid match (inner), skipping expired middle",
		},
		{
			name:         "IP in expired middle range only",
			ip:           "10.1.2.50", // In 10.1.0.0/16 but NOT in 10.1.1.0/24
			shouldFind:   true,
			expectedData: outerData,
			expectedLen:  8,
			description:  "Should skip expired middle and find outer range",
		},
		{
			name:         "IP in outer range only",
			ip:           "10.2.3.4", // In 10.0.0.0/8 but not in any sub-ranges
			shouldFind:   true,
			expectedData: outerData,
			expectedLen:  8,
			description:  "Should find outer range match",
		},
		{
			name:        "IP outside all ranges",
			ip:          "192.168.1.1",
			shouldFind:  false,
			description: "Should not find any match",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			found, data, prefixLen := tree.Contains(ip)

			if found != tt.shouldFind {
				t.Errorf("%s: expected found=%v, got found=%v", tt.description, tt.shouldFind, found)
				return
			}

			if tt.shouldFind {
				if data != tt.expectedData {
					actualData := data.(*types.DecisionData)
					t.Errorf("%s: expected scenario='%s', got scenario='%s'",
						tt.description, tt.expectedData.Scenario, actualData.Scenario)
				}
				if prefixLen != tt.expectedLen {
					t.Errorf("%s: expected prefix length %d, got %d",
						tt.description, tt.expectedLen, prefixLen)
				}
			}
		})
	}

	// Additional verification: Ensure expired node was actually inserted
	// We can verify this by checking that the tree structure allows traversal
	// through the expired node to reach the inner node

	// The key test: IP 10.1.1.50 should find the inner range (10.1.1.0/24)
	// even though it has to traverse through the expired middle range (10.1.0.0/16)
	ip := net.ParseIP("10.1.1.50")
	found, data, prefixLen := tree.Contains(ip)

	if !found {
		t.Error("Critical: Tree traversal failed - expired middle node may be blocking access to inner node")
	}

	if found {
		actualData := data.(*types.DecisionData)
		if actualData.Scenario != "inner-range" {
			t.Errorf("Critical: Expected to find inner-range, got %s - expired node may be interfering", actualData.Scenario)
		}
		if prefixLen != 24 {
			t.Errorf("Critical: Expected prefix 24 (inner), got %d - longest match logic may be broken", prefixLen)
		}
	}
}

func TestRadixTree_AddRemoveConsistency(t *testing.T) {
	tree := NewRadixTree()

	// Define test data for various ranges
	testRanges := map[string]*types.DecisionData{
		"10.0.0.0/8": {
			Type:      "ban",
			Source:    "crowdsec",
			Scenario:  "large-network",
			ExpiresAt: time.Now().Add(1 * time.Hour),
			Value:     "10.0.0.0/8",
		},
		"192.168.0.0/16": {
			Type:      "captcha",
			Source:    "crowdsec",
			Scenario:  "private-network",
			ExpiresAt: time.Now().Add(2 * time.Hour),
			Value:     "192.168.0.0/16",
		},
		"192.168.1.0/24": {
			Type:      "ban",
			Source:    "crowdsec",
			Scenario:  "subnet",
			ExpiresAt: time.Now().Add(30 * time.Minute),
			Value:     "192.168.1.0/24",
		},
		"203.0.113.0/24": {
			Type:      "ban",
			Source:    "manual",
			Scenario:  "test-network",
			ExpiresAt: time.Now().Add(3 * time.Hour),
			Value:     "203.0.113.0/24",
		},
		"172.16.1.100/32": {
			Type:      "captcha",
			Source:    "appsec",
			Scenario:  "single-host",
			ExpiresAt: time.Now().Add(45 * time.Minute),
			Value:     "172.16.1.100/32",
		},
	}

	// Test IPs and their expected matches at different stages
	testIPs := []struct {
		ip          string
		description string
	}{
		{"10.5.10.20", "IP in large network"},
		{"192.168.1.50", "IP in subnet (most specific)"},
		{"192.168.2.10", "IP in private network but not subnet"},
		{"203.0.113.100", "IP in test network"},
		{"172.16.1.100", "Exact single host IP"},
		{"172.16.1.101", "IP near single host but not matching"},
		{"8.8.8.8", "IP outside all ranges"},
	}

	// Helper function to validate current tree state
	validateTreeState := func(stage string, expectedMatches map[string]string) {
		t.Logf("=== Validating tree state: %s ===", stage)
		for _, testIP := range testIPs {
			ip := net.ParseIP(testIP.ip)
			found, data, prefixLen := tree.Contains(ip)

			expectedScenario, shouldFind := expectedMatches[testIP.ip]

			if found != shouldFind {
				t.Errorf("%s - %s: expected found=%v, got found=%v",
					stage, testIP.description, shouldFind, found)
				continue
			}

			if shouldFind && found {
				actualData := data.(*types.DecisionData)
				if actualData.Scenario != expectedScenario {
					t.Errorf("%s - %s: expected scenario='%s', got scenario='%s'",
						stage, testIP.description, expectedScenario, actualData.Scenario)
				}
				t.Logf("  ✓ %s: found '%s' (prefix: %d)", testIP.ip, actualData.Scenario, prefixLen)
			} else {
				t.Logf("  ✓ %s: not found (as expected)", testIP.ip)
			}
		}
	}

	// Stage 1: Empty tree
	t.Log("=== STAGE 1: Empty tree ===")
	validateTreeState("Empty tree", map[string]string{})

	// Stage 2: Add large network
	t.Log("=== STAGE 2: Add 10.0.0.0/8 ===")
	_, cidr1, _ := net.ParseCIDR("10.0.0.0/8")
	tree.Insert(cidr1, testRanges["10.0.0.0/8"])
	validateTreeState("After adding 10.0.0.0/8", map[string]string{
		"10.5.10.20": "large-network",
	})

	// Stage 3: Add private network (creates overlap)
	t.Log("=== STAGE 3: Add 192.168.0.0/16 ===")
	_, cidr2, _ := net.ParseCIDR("192.168.0.0/16")
	tree.Insert(cidr2, testRanges["192.168.0.0/16"])
	validateTreeState("After adding 192.168.0.0/16", map[string]string{
		"10.5.10.20":   "large-network",
		"192.168.1.50": "private-network",
		"192.168.2.10": "private-network",
	})

	// Stage 4: Add subnet (more specific than private network)
	t.Log("=== STAGE 4: Add 192.168.1.0/24 (more specific) ===")
	_, cidr3, _ := net.ParseCIDR("192.168.1.0/24")
	tree.Insert(cidr3, testRanges["192.168.1.0/24"])
	validateTreeState("After adding 192.168.1.0/24", map[string]string{
		"10.5.10.20":   "large-network",
		"192.168.1.50": "subnet",          // Now matches more specific subnet
		"192.168.2.10": "private-network", // Still matches broader network
	})

	// Stage 5: Add test network and single host
	t.Log("=== STAGE 5: Add 203.0.113.0/24 and 172.16.1.100/32 ===")
	_, cidr4, _ := net.ParseCIDR("203.0.113.0/24")
	_, cidr5, _ := net.ParseCIDR("172.16.1.100/32")
	tree.Insert(cidr4, testRanges["203.0.113.0/24"])
	tree.Insert(cidr5, testRanges["172.16.1.100/32"])
	validateTreeState("After adding test network and single host", map[string]string{
		"10.5.10.20":    "large-network",
		"192.168.1.50":  "subnet",
		"192.168.2.10":  "private-network",
		"203.0.113.100": "test-network",
		"172.16.1.100":  "single-host",
	})

	// Stage 6: Try to remove non-existing ranges
	t.Log("=== STAGE 6: Remove non-existing ranges ===")
	_, nonExistentCidr1, _ := net.ParseCIDR("1.2.3.0/24")
	_, nonExistentCidr2, _ := net.ParseCIDR("172.16.2.0/24")

	removed1 := tree.Remove(nonExistentCidr1)
	removed2 := tree.Remove(nonExistentCidr2)

	if removed1 {
		t.Error("Expected removal of non-existent range 1.2.3.0/24 to return false")
	}
	if removed2 {
		t.Error("Expected removal of non-existent range 172.16.2.0/24 to return false")
	}

	// Tree state should be unchanged
	validateTreeState("After attempting to remove non-existent ranges", map[string]string{
		"10.5.10.20":    "large-network",
		"192.168.1.50":  "subnet",
		"192.168.2.10":  "private-network",
		"203.0.113.100": "test-network",
		"172.16.1.100":  "single-host",
	})

	// Stage 7: Remove subnet (should fall back to private network)
	t.Log("=== STAGE 7: Remove 192.168.1.0/24 ===")
	removed3 := tree.Remove(cidr3)
	if !removed3 {
		t.Error("Expected removal of existing range 192.168.1.0/24 to return true")
	}
	validateTreeState("After removing subnet", map[string]string{
		"10.5.10.20":    "large-network",
		"192.168.1.50":  "private-network", // Falls back to broader network
		"192.168.2.10":  "private-network",
		"203.0.113.100": "test-network",
		"172.16.1.100":  "single-host",
	})

	// Stage 8: Remove single host
	t.Log("=== STAGE 8: Remove 172.16.1.100/32 ===")
	removed4 := tree.Remove(cidr5)
	if !removed4 {
		t.Error("Expected removal of existing single host to return true")
	}
	validateTreeState("After removing single host", map[string]string{
		"10.5.10.20":    "large-network",
		"192.168.1.50":  "private-network",
		"192.168.2.10":  "private-network",
		"203.0.113.100": "test-network",
		// 172.16.1.100 should no longer match
	})

	// Stage 9: Try to remove already removed ranges
	t.Log("=== STAGE 9: Try to remove already removed ranges ===")
	removed5 := tree.Remove(cidr3) // subnet already removed
	removed6 := tree.Remove(cidr5) // single host already removed

	if removed5 {
		t.Error("Expected removal of already-removed subnet to return false")
	}
	if removed6 {
		t.Error("Expected removal of already-removed single host to return false")
	}

	// Tree state should be unchanged
	validateTreeState("After attempting to remove already-removed ranges", map[string]string{
		"10.5.10.20":    "large-network",
		"192.168.1.50":  "private-network",
		"192.168.2.10":  "private-network",
		"203.0.113.100": "test-network",
	})

	// Stage 10: Remove broader network (should affect multiple IPs)
	t.Log("=== STAGE 10: Remove 192.168.0.0/16 ===")
	removed7 := tree.Remove(cidr2)
	if !removed7 {
		t.Error("Expected removal of existing private network to return true")
	}
	validateTreeState("After removing private network", map[string]string{
		"10.5.10.20":    "large-network",
		"203.0.113.100": "test-network",
		// 192.168.x.x IPs should no longer match
	})

	// Stage 11: Final cleanup - remove remaining ranges
	t.Log("=== STAGE 11: Remove remaining ranges ===")
	tree.Remove(cidr1) // Remove 10.0.0.0/8
	tree.Remove(cidr4) // Remove 203.0.113.0/24

	// Tree should be empty
	validateTreeState("After removing all ranges", map[string]string{})

	t.Log("=== Test completed successfully - all add/remove operations consistent ===")
}

func TestRadixTree_EdgeCases(t *testing.T) {
	tree := NewRadixTree()

	// Test with nil IP
	found, _, _ := tree.Contains(nil)
	if found {
		t.Error("Expected nil IP to not be found")
	}

	// Test empty tree
	ip := net.ParseIP("1.2.3.4")
	found, _, _ = tree.Contains(ip)
	if found {
		t.Error("Expected IP to not be found in empty tree")
	}

	// Test /0 networks separately (IPv4 and IPv6 catch-all have complex interactions)
	_, ipv4All, _ := net.ParseCIDR("0.0.0.0/0")
	tree.Insert(ipv4All, "ipv4-all")

	// Test IPv4 IPs
	ipv4IPs := []string{"1.2.3.4", "255.255.255.255"}
	for _, ipStr := range ipv4IPs {
		ip := net.ParseIP(ipStr)
		found, data, _ := tree.Contains(ip)
		if !found {
			t.Errorf("Expected IPv4 IP %s to be found in catch-all", ipStr)
			continue
		}
		if data != "ipv4-all" {
			t.Errorf("IPv4 IP %s: expected data 'ipv4-all', got '%v'", ipStr, data)
		}
	}
}

func TestRadixTree_ComplexScenario(t *testing.T) {
	tree := NewRadixTree()

	// Build a complex tree with multiple overlapping ranges
	ranges := []struct {
		cidr string
		data string
	}{
		{"0.0.0.0/0", "global"},         // Catch-all
		{"10.0.0.0/8", "private-a"},     // Class A private
		{"192.168.0.0/16", "private-c"}, // Class C private
		{"192.168.1.0/24", "subnet"},    // Specific subnet
		{"192.168.1.100/32", "host"},    // Single host
		{"172.16.0.0/12", "private-b"},  // Class B private
	}

	for _, r := range ranges {
		_, cidr, err := net.ParseCIDR(r.cidr)
		if err != nil {
			t.Fatalf("Failed to parse CIDR %s: %v", r.cidr, err)
		}
		tree.Insert(cidr, r.data)
	}

	// Test various IPs to ensure most specific match
	tests := []struct {
		ip           string
		expectedData string
		expectedLen  int
	}{
		{"192.168.1.100", "host", 32},    // Most specific
		{"192.168.1.50", "subnet", 24},   // Subnet level
		{"192.168.2.1", "private-c", 16}, // Network level
		{"10.5.10.15", "private-a", 8},   // Different private network
		{"172.16.1.1", "private-b", 12},  // Another private network
		{"8.8.8.8", "global", 0},         // Public IP (catch-all)
	}

	for _, tt := range tests {
		ip := net.ParseIP(tt.ip)
		found, data, prefixLen := tree.Contains(ip)
		if !found {
			t.Errorf("Expected IP %s to be found", tt.ip)
			continue
		}
		if data != tt.expectedData {
			t.Errorf("IP %s: expected data '%s', got '%v'", tt.ip, tt.expectedData, data)
		}
		if prefixLen != tt.expectedLen {
			t.Errorf("IP %s: expected prefix length %d, got %d", tt.ip, tt.expectedLen, prefixLen)
		}
	}
}

// Benchmark tests
func BenchmarkRadixTree_Insert(b *testing.B) {
	tree := NewRadixTree()
	_, cidr, _ := net.ParseCIDR("192.168.1.0/24")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tree.Insert(cidr, "test-data")
	}
}

func BenchmarkRadixTree_Contains(b *testing.B) {
	tree := NewRadixTree()
	_, cidr, _ := net.ParseCIDR("192.168.1.0/24")
	tree.Insert(cidr, "test-data")
	ip := net.ParseIP("192.168.1.100")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tree.Contains(ip)
	}
}

func BenchmarkRadixTree_ContainsLargeTree(b *testing.B) {
	tree := NewRadixTree()

	// Insert many ranges
	ranges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"203.0.113.0/24",
		"198.51.100.0/24",
		"2001:db8::/32",
		"fe80::/10",
	}

	for i, r := range ranges {
		_, cidr, _ := net.ParseCIDR(r)
		tree.Insert(cidr, fmt.Sprintf("data-%d", i))
	}

	ip := net.ParseIP("192.168.1.100")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tree.Contains(ip)
	}
}
