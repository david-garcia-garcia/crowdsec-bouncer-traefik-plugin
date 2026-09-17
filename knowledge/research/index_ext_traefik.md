# ext / traefik

## Local plugins
priority: normal
local: ext_traefik_plugins_localplugins/
description: How Traefik loads a plugin from a bind-mounted module path instead of the catalog.

## Yaegi middleware constructor
priority: normal
local: ext_traefik_plugins_yaegi-constructor/
description: Where Traefik Yaegi looks up CreateConfig and New, how often New runs, and whether Config and subpackages must live in the root package.

## Plugin manifest useUnsafe
priority: normal
local: ext_traefik_plugins_useunsafe/
description: What the useUnsafe manifest flag unlocks in the Yaegi plugin host, and the matching operator opt-in a Traefik installation must also set.

