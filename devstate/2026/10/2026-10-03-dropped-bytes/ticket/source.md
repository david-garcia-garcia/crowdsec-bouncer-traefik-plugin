Send dropped bytes to CrowdSec LAPI usage-metrics the way the firewall bouncer does: an additional `dropped` item whose unit is `byte`, estimated from the HTTP request this plugin already has, without reading the body.

Estimate the request size from fields on `*http.Request` (and the clientrequest wrapper that embeds it):

- `len(RequestURI)` for the request-target as sent
- `len(Host)` because the server lifts Host out of the Header map
- length of each header name and each header value already in `Header`
- the declared `ContentLength` when it is `>= 0`

Do not read `Body`. Do not call `httputil.DumpRequest` or `Request.Write`. Do not send unit `packet`.

Cap content-length: if the request reports `ContentLength` greater than 50 mebibytes (50 * 1024 * 1024), count 50 mebibytes for that part. The human wrote "50Mb"; use 50 MiB (52428800 bytes).

Storage must not overflow over time. The running byte counters (the usage-metrics window that is summed until the next successful POST, including a failed POST that restores the window) must saturate instead of wrapping. A single request's capped estimate must also fit the counter type.

Keep the existing `dropped` / `processed` items whose unit is `request`. This adds the byte series. It does not replace request counts.

Out of scope for the ask (do not take them as requirements): reading the body when ContentLength is -1; estimating packets; sending `processed` with unit `byte`; putting the estimate in the firewall bouncer's own table (cscli already prints one table per bouncer).
