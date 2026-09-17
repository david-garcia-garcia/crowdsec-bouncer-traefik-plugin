# AppSec bot-detection challenge (CrowdSec 1.8.0) is not Supported YET

Source: https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/389
State: open
Opened by: bondskin
Related implementation PR: https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/343

## Title
AppSec bot-detection challenge (CrowdSec 1.8.0) is never resolved when routed through the plugin — silently blocks all traffic

## Environment
- CrowdSec Security Engine: **1.8.0**
- crowdsec-bouncer-traefik-plugin: **v1.7.1**
- Traefik: v3.7.x
- Deployment: Docker (crowdsec engine + Traefik + plugin, all on the same Docker network)

## Description

After upgrading CrowdSec to 1.8.0 and enabling the new bot-detection collection (`crowdsecurity/appsec-bot-*`) in the AppSec acquisition, all traffic routed through Traefik with the `crowdsecAppsecEnabled: true` middleware starts returning **403** — even though `cscli metrics show appsec` shows `Blocked: 0` (i.e. no actual WAF rule is blocking anything). Accessing the same backend directly (bypassing Traefik/AppSec) works fine.

The CrowdSec engine logs repeated write errors on the AppSec listener while this happens:

```
time=2026-09-03T12:31:51+02:00
level=error
msg=unable to write response: write tcp 172.25.0.210:7422->172.25.0.240:43210: write: broken pipe
client_ip=192.168.2.178
module=acquisition.appsec
request_uuid=3e93e665-c9f0-4013-9315-51c95389690f
type=appsec
```

`cscli metrics show appsec` (Bot Detection section) shows challenges being requested but never resolved:

```
Bot Detection Metrics
Requested: 34   Submitted: -   Solved: -   Granted: -   Exempt: 2.15k
Ch. Requested: 34   Ch. Accepted: -   Ch. Rejected: -
```

So the AppSec engine issues the challenge page, but the connection to the plugin is closed (broken pipe / connection reset by peer) before the challenge response can be written — the challenge is never delivered to the client, so it can never be submitted/solved. The end result for the user is an indefinite 403 on every request.

The CrowdSec docs explicitly call this out as an expected failure mode for unsupported bouncers:

> "Check that your bouncer supports bot detection before going further [...] Enabling it behind a bouncer that does not support it leads to unexpected behavior, most likely silently refusing every client."
> — https://docs.crowdsec.net/docs/v1.8/appsec/bot_detection/enable

## Relevant middleware config

```yaml
my-crowdsec:
  plugin:
    crowdsec:
      enabled: true
      crowdsecLapiHost: "crowdsec:8080"
      crowdsecLapiScheme: http
      crowdsecLapiKey: "<redacted>"
      updateIntervalSeconds: 30
      crowdsecMode: live
      crowdsecAppsecEnabled: true
      crowdsecAppsecHost: crowdsec:7422
      crowdsecAppsecFailureBlock: true
      crowdsecAppsecUnreachableBlock: true
      crowdsecAppsecScheme: http
      crowdsecAppsecPath: "/"
      crowdsecAppsecBodyLimit: 10485760
      crowdsecLapiPath: "/"
      crowdsecLapiTLSInsecureVerify: false
```

Relevant AppSec acquisition on the engine side (`/etc/crowdsec/acquis.d/appsec.yaml`):

```yaml
listen_addr: 0.0.0.0:7422
appsec_configs:
  - crowdsecurity/appsec-default
  - crowdsecurity/appsec-bot-*
source: appsec
labels:
  type: appsec
```

## Steps to reproduce

1. Run CrowdSec 1.8.0 with `crowdsecurity/appsec-bot-*` loaded in the AppSec acquisition.
2. Run crowdsec-bouncer-traefik-plugin v1.7.1 with `crowdsecAppsecEnabled: true` pointed at that AppSec listener.
3. Send a normal browser request to a route protected by the middleware.
4. Observe: request is blocked (403), engine logs `unable to write response ... broken pipe`, and `cscli metrics show appsec` shows the bot-detection challenge as requested but never accepted/rejected.

## Expected behavior
Either:
- the plugin correctly proxies/relays the bot-detection challenge (fingerprinting page + `/crowdsec-internal/challenge/*` callback) so the client can solve it and gain access, or
- if bot-detection isn't yet supported by the plugin, some documented/graceful fallback instead of a silent, permanent block.

## Actual behavior
Every request is blocked with 403. No indication in the plugin's own logs of *why* — the only clue is on the CrowdSec engine side (broken pipe on the AppSec write).

## Workaround
Setting `crowdsecAppsecEnabled: false` in the middleware restores normal access (IP-reputation checks via `crowdsecMode: live` still work; only AppSec/WAF/bot-detection is bypassed for Traefik-routed traffic). We're running the AppSec bot-detection separately via a different (nginx-based) bouncer that seems to handle it correctly.

## Maintainer note (issue comment)

mathieuHa: this is not a bug; the plugin does not support bot detection yet. Ongoing PR: https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/343

## Caller addendum

Implement bot detection in this fork (`destBranch: master`). Use upstream issue 389 and PR 343 as the protocol source. Good test coverage, including real e2e tests. Work is done when the PR passes CI and the delivery card is on the PR summary.
