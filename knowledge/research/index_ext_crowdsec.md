# ext / crowdsec

## Docker environment variables
priority: normal
local: ext_crowdsec_docker_environment/
description: How the Crowdsec Docker image registers bouncers and hub collections at container start.

## cscli decisions
priority: normal
local: ext_crowdsec_cscli_decisions/
description: How tests inject and clear remediations on a real Crowdsec LAPI.

## Decision scopes
priority: normal
local: ext_crowdsec_decisions_scopes/
description: Official CrowdSec decision scope values a bouncer can receive and how each is matched.

## AppSec bot-detection challenge
priority: normal
local: ext_crowdsec_appsec_bot-detection/
description: CrowdSec AppSec challenge-mode wire protocol a bouncer must implement to serve bot detection.

## LAPI stream cursor
priority: normal
local: ext_crowdsec_lapi_stream-cursor/
description: Where CrowdSec LAPI stores /v1/decisions/stream progress and which bouncer row owns it.
