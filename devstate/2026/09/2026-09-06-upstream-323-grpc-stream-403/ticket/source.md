# upstream#323

- title: [BUG] Silently returns 403 on gRPC streaming connections
- state: CLOSED
- url: https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/323
- created: 2026-04-30T14:11:23Z
- updated: 2026-07-28T13:51:16Z
- labels: bug, enhancement

## Body

**Describe the bug** 🐛
After upgrading from v1.5.1 to v1.6.0, the plugin breaks gRPC connections that was previously working. First saw this behavior with self hosted instance of NetBird, where all connections to "/signalexchange.SignalExchange/ConnectStream" gets a DownstreamStatus 403. Reverting to v1.5.1 fixes this problem, no other changes were made to NetBird or Traefik. 

**Expected behavior** 👀
gRPC connections should pass through the bouncer without interference when no Crowdsec decision exists for the client IP.

**Context** 🔎
The plugin is applied as an entrypoint-level middleware on the `websecure` entrypoint, so applied to all HTTPs requests. Traefik terminates TLS and forwards gRPC via `h2c` to the backend.
NetBird uses long-lived gRPC requests to the "/signalexchange.SignalExchange/ConnectStream" endpoint. 
Crowdsec logs no block actions with "cscli decisions list", even a manual allow for clients does not work. (via cscli decisions add --type allow)

Other Observations
- `OriginStatus: 0` and `OriginDuration: 0` shows the request never reached the backend. Crowdsec plugin returned the 403 itself.
- The same client IP successfully completes `GetServerKey` and `Login` gRPC calls (both return `Grpc-Status: 0`) moments before the `ConnectStream` call is blocked.
- `cscli decisions list` shows no decisions for the affected IPs. No logs from this plugin than "msg=handleStreamCache:updated" in Traefik container. 
- No ban/block entries appear in plugin logs even at `DEBUG` level.
- WebSocket connections and standard HTTPS work fine through the same entrypoint. 

Anonymized section of access logs:
```json
# Plugin version v1.6.0
{"ClientAddr":"x.x.x.x:34834","ClientHost":"x.x.x.x","ClientPort":"34834","ClientUsername":"-","DownstreamContentSize":61,"DownstreamStatus":200,"Duration":4369274,"OriginContentSize":61,"OriginDuration":1497998,"OriginStatus":200,"Overhead":2871276,"RequestAddr":"netbird.example.com:443","RequestContentSize":5,"RequestCount":378,"RequestHost":"netbird.example.com","RequestMethod":"POST","RequestPath":"/management.ManagementService/GetServerKey","RequestPort":"443","RequestProtocol":"HTTP/2.0","RequestScheme":"https","RetryAttempts":0,"RouterName":"websecure-netbird-management@docker","ServiceAddr":"172.20.0.7:443","ServiceName":"netbird-management@docker","ServiceURL":"h2c://172.20.0.7:443","StartLocal":"2026-04-30T21:58:47.720064751+10:00","StartUTC":"2026-04-30T11:58:47.720064751Z","TLSCipher":"TLS_CHACHA20_POLY1305_SHA256","TLSVersion":"1.3","downstream_Alt-Svc":"h3=\":443\"; ma=2592000","downstream_Content-Type":"application/grpc","downstream_Grpc-Status":"0","downstream_Trailer":"Grpc-Message, Grpc-Status-Details-Bin, Grpc-Status","entryPointName":"websecure","level":"info","msg":"","origin_Alt-Svc":"h3=\":443\"; ma=2592000","origin_Content-Type":"application/grpc","origin_Grpc-Status":"0","origin_Trailer":"Grpc-Message, Grpc-Status-Details-Bin, Grpc-Status","request_Content-Type":"application/grpc","request_Grpc-Timeout":"4999939u","request_Te":"trailers","request_User-Agent":"grpc-go/1.79.3","request_X-Forwarded-Host":"netbird.example.com:443","request_X-Forwarded-Port":"443","request_X-Forwarded-Proto":"https","request_X-Forwarded-Server":"REDACTED","request_X-Is-Trusted":"no","request_X-Real-Ip":"x.x.x.x","time":"2026-04-30T21:58:47+10:00"}
{"ClientAddr":"x.x.x.x:34834","ClientHost":"x.x.x.x","ClientPort":"34834","ClientUsername":"-","DownstreamContentSize":419,"DownstreamStatus":200,"Duration":112920433,"OriginContentSize":419,"OriginDuration":109881237,"OriginStatus":200,"Overhead":3039196,"RequestAddr":"netbird.example.com:443","RequestContentSize":296,"RequestCount":379,"RequestHost":"netbird.example.com","RequestMethod":"POST","RequestPath":"/management.ManagementService/Login","RequestPort":"443","RequestProtocol":"HTTP/2.0","RequestScheme":"https","RetryAttempts":0,"RouterName":"websecure-netbird-management@docker","ServiceAddr":"172.20.0.7:443","ServiceName":"netbird-management@docker","ServiceURL":"h2c://172.20.0.7:443","StartLocal":"2026-04-30T21:58:47.745063554+10:00","StartUTC":"2026-04-30T11:58:47.745063554Z","TLSCipher":"TLS_CHACHA20_POLY1305_SHA256","TLSVersion":"1.3","downstream_Alt-Svc":"h3=\":443\"; ma=2592000","downstream_Content-Type":"application/grpc","downstream_Grpc-Status":"0","downstream_Trailer":"Grpc-Status, Grpc-Message, Grpc-Status-Details-Bin","entryPointName":"websecure","level":"info","msg":"","origin_Alt-Svc":"h3=\":443\"; ma=2592000","origin_Content-Type":"application/grpc","origin_Grpc-Status":"0","origin_Trailer":"Grpc-Status, Grpc-Message, Grpc-Status-Details-Bin","request_Content-Type":"application/grpc","request_Grpc-Timeout":"9999563u","request_Te":"trailers","request_User-Agent":"grpc-go/1.79.3","request_X-Forwarded-Host":"netbird.example.com:443","request_X-Forwarded-Port":"443","request_X-Forwarded-Proto":"https","request_X-Forwarded-Server":"REDACTED","request_X-Is-Trusted":"no","request_X-Real-Ip":"x.x.x.x","time":"2026-04-30T21:58:47+10:00"}
{"ClientAddr":"x.x.x.x:34779","ClientHost":"x.x.x.x","ClientPort":"34779","ClientUsername":"-","DownstreamContentSize":0,"DownstreamStatus":403,"Duration":19808199303,"OriginContentSize":0,"OriginDuration":0,"OriginStatus":0,"Overhead":19808199303,"RequestAddr":"netbird.example.com:443","RequestContentSize":0,"RequestCount":131,"RequestHost":"netbird.example.com","RequestMethod":"POST","RequestPath":"/signalexchange.SignalExchange/ConnectStream","RequestPort":"443","RequestProtocol":"HTTP/2.0","RequestScheme":"https","RetryAttempts":0,"RouterName":"websecure-netbird-signal@docker","StartLocal":"2026-04-30T21:33:11.203370405+10:00","StartUTC":"2026-04-30T11:33:11.203370405Z","TLSCipher":"TLS_CHACHA20_POLY1305_SHA256","TLSVersion":"1.3","downstream_Alt-Svc":"h3=\":443\"; ma=2592000","downstream_Content-Type":"","entryPointName":"websecure","level":"info","msg":"","request_Content-Type":"application/grpc","request_Te":"trailers","request_User-Agent":"grpc-go/1.79.3","request_X-Forwarded-Host":"netbird.example.com:443","request_X-Forwarded-Port":"443","request_X-Forwarded-Proto":"https","request_X-Forwarded-Server":"REDACTED","request_X-Is-Trusted":"no","request_X-Real-Ip":"x.x.x.x","request_X-Wiretrustee-Peer-Id":"REDACTED","time":"2026-04-30T21:33:31+10:00"}


# Plugin version v1.5.1
{"ClientAddr":"x.x.x.x:36722","ClientHost":"x.x.x.x","ClientPort":"36722","ClientUsername":"-","DownstreamContentSize":0,"DownstreamStatus":200,"Duration":60002434127,"OriginContentSize":0,"OriginDuration":0,"OriginStatus":0,"Overhead":60002434127,"RequestAddr":"netbird.example.com:443","RequestContentSize":0,"RequestCount":505,"RequestHost":"netbird.example.com","RequestMethod":"POST","RequestPath":"/signalexchange.SignalExchange/ConnectStream","RequestPort":"443","RequestProtocol":"HTTP/2.0","RequestScheme":"https","RetryAttempts":0,"RouterName":"websecure-netbird-signal@docker","ServiceAddr":"172.20.0.3:10000","ServiceName":"netbird-signal@docker","ServiceURL":"h2c://172.20.0.3:10000","StartLocal":"2026-04-30T23:03:54.803698489+10:00","StartUTC":"2026-04-30T13:03:54.803698489Z","TLSCipher":"TLS_CHACHA20_POLY1305_SHA256","TLSVersion":"1.3","downstream_Alt-Svc":"h3=\":443\"; ma=2592000","downstream_Content-Type":"application/grpc","downstream_X-Wiretrustee-Peer-Registered":"1","entryPointName":"websecure","level":"info","msg":"","request_Content-Type":"application/grpc","request_Te":"trailers","request_User-Agent":"grpc-go/1.80.0","request_X-Forwarded-Host":"netbird.example.com:443","request_X-Forwarded-Port":"443","request_X-Forwarded-Proto":"https","request_X-Forwarded-Server":"REDACTED","request_X-Is-Trusted":"no","request_X-Real-Ip":"y.y.y.y","request_X-Wiretrustee-Peer-Id":"REDACTED","time":"2026-04-30T23:04:54+10:00"}
```

**Version (please complete the following information):**
 - OS: Ubuntu 24.04.4 LTS, Docker v29.4.1
 - Traefik version: 3.6.14 & 3.6.15
 - Plugin version: v1.6.0

**To Reproduce**
Steps to reproduce the behavior:
1. Upgrade the plugin from v1.5.1 to v1.6.0 in Traefik config.
2. Apply the bouncer middleware to an entrypoint or router that handles gRPC traffic
3. Attempt to connect a NetBird peer / initiate gRPC traffic
4. Observe that `ConnectStream` receives 403 in Traefik access logs with `OriginStatus: 0`. Peers do not register as connected on the server side despite `Login` calls appearing to succeed in access logs.
5. Run `netbird status`, management and signal both show "Disconnected, reason: reset connection" or just hangs.
6. Check that no CrowdSec decisions exist for the client IP.

---

# Assessment: upstream#323

- relevant: yes
- kind: bug
- affected: yes
- status: present-unfixed
- proof: pkg/appsec/query_test.go
- recommended-action: fix
- slug: 2026-09-06-upstream-323-grpc-stream-403
- rationale: Upstream #323 is an AppSec regression: v1.6.0 buffered HTTP/2 POST bodies with no Content-Length, so gRPC streams like NetBird `ConnectStream` blocked on `io.ReadAll` then returned a silent plugin 403 with no LAPI decision; reporters confirmed AppSec must be enabled. Our fork fixed the hang in `pkg/appsec/query.go` via `isBodyUnreadable` and headers-only GET when `crowdsecAppsecFailureAction` is `passthrough` (`Test_appsecQuery_streamingDoesNotBlock`), but default config still drops streaming POSTs: `CrowdsecAppsecFailureAction` defaults to `ban` in `pkg/configuration/configuration.go`, and `newAppsecBodyRequest` returns `appsecQuery:unreadableBody dropped`, which `pkg/bouncer/bouncer.go` remediates as 403 — matching the reported symptom for AppSec-enabled deployments unless operators set `passthrough` (the upstream default after #332).

## Evidence
- current: pkg/appsec/query.go, pkg/bouncer/bouncer.go, pkg/configuration/configuration.go
- tests: pkg/appsec/query_test.go
