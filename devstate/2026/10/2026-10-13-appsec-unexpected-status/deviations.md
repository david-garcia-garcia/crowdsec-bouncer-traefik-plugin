# Deviations

- [x] taken  403 empty/invalid JSON stays fail-closed ban
  Asked: a status that is not 200, not 502/503/504, and not a parseable JSON action follows `bouncerAppsecFailureAction` (so a bare 403 would passthrough when configured).
  Instead: HTTP 403 with empty or invalid JSON keeps today's Query error, which the bouncer bans. 401 and other unexpected statuses follow FailureAction.
  Owner: `pkg/appsec/query.go` `interpretAppsecBody`
  Why: the challenge protocol already owns 403 as the verdict channel and fail-closes empty/invalid JSON; honouring the letter would add a FailureAction branch on that channel.
  By: explore
  Requester: not asked
