# core / cache

## DecisionStore cache
priority: normal
local: core_cache_client.md
description: How LAPI Clients share one DecisionStore keyed by CrowdSec cursor plus Redis params.

## Origin dictionary
priority: normal
local: core_cache_client_origin-dictionary.md
description: How one DecisionStore interns MetricsOrigin names and stores packed memory remediations.

## Redis cache client
priority: normal
local: core_cache_redis.md
description: How this plugin talks to a Redis-protocol cache (vendored utilities SimpleRedis).
