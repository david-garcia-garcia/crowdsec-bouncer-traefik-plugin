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

## Stream apply order
priority: normal
local: ext_crowdsec_bouncers_stream-apply/
description: How official CrowdSec bouncers apply new vs deleted on one /v1/decisions/stream payload.

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

## Watcher login response
priority: normal
local: ext_crowdsec_watchers_login-response/
description: What CrowdSec returns on watchers/login and how official apiclient stores Token after HTTP 2xx.

## CAPI watchers login
priority: normal
local: ext_crowdsec_capi_watchers-login/
description: What CrowdSec CAPI accepts on POST /watchers/login and which fields the official client sends.
