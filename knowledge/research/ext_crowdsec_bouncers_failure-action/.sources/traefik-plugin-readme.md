---
url: https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/blob/04d928872df12bdb9d953b2d92948e0b89692d6a/README.md
title: crowdsec-bouncer-traefik-plugin README configuration
fetched: 2026-09-05
authority: source
ref: github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin@04d928872df12bdb9d953b2d92948e0b89692d6a:README.md
---

CrowdsecAppsecFailureBlock bool default true: block when AppSec returns status 500 (links protocol response-code).

CrowdsecAppsecUnreachableBlock bool default true: block when AppSec is unreachable.

UpdateMaxFailure int64 default 0: stream and alone only. Maximum number of times we cannot reach Crowdsec before blocking traffic. Set -1 to never block.

StreamStartupBlock bool default true: stream and alone. When true, init waits for Crowdsec. When false, all requests bypass remediation until the first stream sync completes.

HTTPTimeoutSeconds default 10: timeout contacting LAPI.

CrowdsecMode default live: none, live, stream, alone, appsec.

RedisCacheUnreachableBlock bool default true.

CrowdsecAppsecUnreadableBodyBlock: README says default false. Conflicts with configuration.New() default true at this commit.
