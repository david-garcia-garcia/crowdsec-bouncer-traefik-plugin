# Example: ModSecurity CRS next to CrowdSec

One Traefik middleware checks every request against CrowdSec decisions (LAPI), CrowdSec AppSec, and an OWASP CRS sidecar running ModSecurity. CrowdSec also reads the sidecar's log, so an IP that keeps tripping CRS gets a CrowdSec ban.

| File | What it is |
| --- | --- |
| [docker-compose.yml](docker-compose.yml) | Traefik with the plugin, `whoami` as the application, the CRS sidecar `waf`, and CrowdSec. |
| [dynamic.yml](dynamic.yml) | The middlewares. `crowdsec` connects to LAPI, AppSec, and the sidecar and protects `/`. `crowdsec-admin` reuses the three connections for `/admin` and bans when the sidecar is down. |
| [crs-apache/httpd-vhosts.conf](crs-apache/httpd-vhosts.conf) | Makes the sidecar inspect-only: after CRS, Apache answers 200 itself instead of proxying anywhere. |
| [crs-rules/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf](crs-rules/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf) | Two local rules: reject a body on `DELETE` and `OPTIONS`, and let `/api/search` take a `GET` with a body. |
| [acquis.yaml](acquis.yaml) | CrowdSec reads the Traefik access log, serves AppSec on port 7422, and reads the sidecar log (`type: modsecurity`). |

## Run it

From the repository root:

```bash
make run_modsecurity
```

Give CrowdSec about 20 seconds to install its collections on the first start.

## Try it

`X-Crowdsec-Remediation` tells which check answered. Every result below was checked against this stack.

```bash
# Clean request: 200, no remediation header.
curl -i http://localhost:8000/

# Path traversal in the query string: CRS blocks it. 403, X-Crowdsec-Remediation: ban:modsec
curl -i "http://localhost:8000/?file=../../etc/passwd"

# XSS in a form body: the body reaches CRS. 403, ban:modsec
curl -i -X POST --data-urlencode 'q=<script>alert(1)</script>' http://localhost:8000/form

# GET with a body: CRS rule 920170 blocks it. 403, ban:modsec
curl -i -X GET -H 'Content-Type: application/json' --data '{"q":1}' http://localhost:8000/x

# The same on /api/search: the local exception (rule 1000200) lets it through. 200
curl -i -X GET -H 'Content-Type: application/json' --data '{"q":1}' http://localhost:8000/api/search

# DELETE is allowed because ALLOWED_METHODS lists it. 200
curl -i -X DELETE http://localhost:8000/items/1

# DELETE with a body: the local rule 1000100 answers 400. 400, ban:modsec
curl -i -X DELETE -H 'Content-Type: application/json' --data '{"a":1}' http://localhost:8000/items/1

# CrowdSec AppSec virtual patching runs before the sidecar. 403, ban:appsec
curl -i http://localhost:8000/.env
```

## See why a request was blocked

The plugin only learns "allow" or "block". The details are in the sidecar's error log, one line per rule:

```bash
docker logs waf 2>&1 | grep "ModSecurity: "
```

```text
[...] [security2:error] [...] [client 172.18.0.1] ModSecurity: Access denied with code 403 (phase 2). Operator GE matched 5 at TX:blocking_inbound_anomaly_score. [file "/etc/modsecurity.d/owasp-crs/rules/REQUEST-949-BLOCKING-EVALUATION.conf"] [line "233"] [id "949110"] [msg "Inbound Anomaly Score Exceeded (Total Score: 5)"] [...] [uri "/x"] [unique_id "..."]
```

Read `id` and `msg` on the lines just before the `Access denied` line: they name the rules that added to the score. `[client ...]` is the visitor's IP as Traefik sent it in `X-Real-IP`.

CrowdSec reads the same lines:

```bash
docker exec crowdsec cscli metrics show acquisition
```

The `docker:waf` row counts lines read and parsed by `crowdsecurity/modsecurity`. In this local demo every client is a private address, so the lines are whitelisted and no ban follows. Behind a real public IP, the `crowdsecurity/modsecurity` scenario turns repeated CRS hits into a CrowdSec decision, and the plugin then bans that IP before any WAF runs.

## Stop it

```bash
docker compose -f examples/modsecurity/docker-compose.yml down -v
```
