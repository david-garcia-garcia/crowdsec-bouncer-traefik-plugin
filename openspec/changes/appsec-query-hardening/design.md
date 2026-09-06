## Context

`Client.Query` builds a POST (or GET) to the AppSec listener, copies client headers, and interprets the JSON envelope. Four early-return paths bypass connection drain or failure-action policy.

## Goals / Non-Goals

**Goals**
- Connection reuse on 502/503/504 identical to 200/500.
- Outbound `Content-Length` matches truncated or full forwarded body.
- Read errors honor per-router `crowdsecAppsecFailureAction`.
- Document and implement `0` body limit as unlimited.

**Non-Goals**
- Change `pkg/configuration` validation for body limit.
- Refactor hop-by-hop helpers into a shared package.
- Alter AppSec verdict handling for non-infrastructure HTTP statuses.

## Decisions

1. **Defer drain immediately after non-nil `Do` response** — single `defer c.drainResponse(res)` guarded by `res != nil`.
2. **Header filter in `newAppsecForwardRequest`** — skip hop-by-hop, `Content-Length`, `Transfer-Encoding`; set `Content-Length` from `req.ContentLength` after POST body build.
3. **Read errors → `resultForFailureAction`** — same logging tier as 500 (`appsecQuery:failure`).
4. **Body limit 0 = unlimited** — `io.ReadAll` without `LimitReader`; restore client body for downstream.

## Risks / Trade-offs

- Unlimited body at limit `0` can increase memory use — operator opt-in by setting `0` explicitly; default remains 10 MiB.

## Migration

No config migration. Operators who relied on silent drop at `0` will now forward full bodies; `0` was undocumented.
