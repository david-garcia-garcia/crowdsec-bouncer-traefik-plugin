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

## AppSec protocol
priority: normal
local: ext_crowdsec_appsec_protocol/
description: Official CrowdSec AppSec HTTP verdict codes a remediation component must honour.

## Bouncer failure action
priority: normal
local: ext_crowdsec_bouncers_failure-action/
description: How CrowdSec bouncers behave when LAPI or AppSec is down, times out, or returns 500.

## AppSec bot-detection challenge
priority: normal
local: ext_crowdsec_appsec_bot-detection/
description: CrowdSec AppSec challenge-mode wire protocol a bouncer must implement to serve bot detection.

## LAPI stream cursor
priority: normal
local: ext_crowdsec_lapi_stream-cursor/
description: Where CrowdSec LAPI stores /v1/decisions/stream progress and which bouncer row owns it.

## LAPI usage-metrics
priority: normal
local: ext_crowdsec_lapi_usage-metrics/
description: What CrowdSec LAPI accepts on POST /v1/usage-metrics and which labels official bouncers send.

## AppSec unreadable body
priority: normal
local: ext_crowdsec_appsec_unreadable-body/
description: How reference bouncers handle HTTP/2+ bodies without Content-Length (APPSEC_DROP_UNREADABLE_BODY / gRPC streams).
