# traefik-middleware-utilities

## Packages layout and APIs
priority: normal
local: ext_traefik-middleware-utilities_packages/
description: Where reclaim and simpleredis live in the utilities repo and how their APIs differ from in-tree copies.

## traefikemulator
priority: normal
local: ext_traefik-middleware-utilities_traefikemulator/
description: Published generation-Apply test helper at utilities v1.0.7.

## reclaim alias
priority: normal
local: ext_traefik-middleware-utilities_reclaim_alias/
description: Published SetAlias/Watch/ClearPublisher and Peek on utilities reclaim at v1.0.7.

## windowcounter sliding window
priority: normal
local: ext_traefik-middleware-utilities_windowcounter/
description: Published windowcounter Limiter surface at utilities v1.0.7, its Yaegi status, and which reproduced defects are fixed or still open there.

## tokenbucket Allow
priority: normal
local: ext_traefik-middleware-utilities_tokenbucket/
description: Published tokenbucket Memory/Redis surface at utilities v1.0.7, its Yaegi status, and the maxDelay-units fail-open still open there.
