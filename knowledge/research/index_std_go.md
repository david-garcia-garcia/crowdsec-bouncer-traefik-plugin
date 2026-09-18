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
