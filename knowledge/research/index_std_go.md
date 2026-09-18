## Go test _test.go filename suffix
priority: normal
local: std_go_go-test_test-filename-suffix/
description: Which basenames go test treats as test sources when building test binaries.

## LimitReader zero limit
priority: normal
local: std_go_io_limit-reader/
description: How io.LimitReader behaves when the remaining-byte count is zero or negative.

## HTTP keep-alive response drain
priority: normal
local: std_go_net-http_keep-alive-drain/
description: When net/http.Client.Do can reuse a persistent TCP connection.

## Request ContentLength
priority: normal
local: std_go_net-http_request-content-length/
description: How the Go HTTP client chooses outbound Content-Length from the field versus the header.

## IPv6 zone ID parse
priority: normal
local: std_go_net_ipv6-zone/
description: How Go net.ParseIP, SplitHostPort, and TCPAddr treat RFC 4007 IPv6 zone IDs.

## IPv4-mapped CIDR Contains
priority: normal
local: std_go_net_ipv4-mapped-cidr/
description: How Go ParseCIDR and IPNet.Contains treat IPv4-mapped IPv6 CIDRs.
