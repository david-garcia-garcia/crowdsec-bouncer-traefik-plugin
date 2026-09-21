# std / go

## Reclaim context lease
priority: normal
local: std_go_reclaim.md
description: How this product binds a process table value to Traefik constructor context.

## zzz_ test file
priority: normal
local: std_go_test_zzz-prefix.md
description: How this repository names in-repo Go test sources.

## Test log sink
priority: normal
local: std_go_test_log-sink.md
description: How an in-repo test captures slog output when the code under test logs from its own goroutines.

## Request-path Debug attributes
priority: normal
local: std_go_logger_debug-attrs.md
description: How request-path Debug passes slog attributes so INFO does not format a string.
