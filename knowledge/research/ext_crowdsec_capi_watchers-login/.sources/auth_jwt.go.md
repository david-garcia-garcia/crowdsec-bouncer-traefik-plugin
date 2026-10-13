---
url: https://github.com/crowdsecurity/crowdsec/blob/fc1677ba/pkg/apiclient/auth_jwt.go
title: JWTTransport refreshJwtToken login encode
fetched: 2026-09-18
authority: source
ref: github.com/crowdsecurity/crowdsec@fc1677ba:pkg/apiclient/auth_jwt.go
---

refreshJwtToken builds models.WatcherAuthRequest{MachineID, Password, Scenarios}.
Encodes with json.NewEncoder; SetEscapeHTML(false); Encode(auth).
POSTs fmt.Sprintf("%s%s/watchers/login", t.URL, t.VersionPrefix).
Sets Content-Type application/json. Optional User-Agent.
Does not sprintf-interpolate credentials into a JSON string.
prepareRequest skips token refresh when Path is /{VersionPrefix}/watchers/login.
