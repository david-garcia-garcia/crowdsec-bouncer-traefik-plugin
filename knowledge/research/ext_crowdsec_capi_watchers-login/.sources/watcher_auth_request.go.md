---
url: https://github.com/crowdsecurity/crowdsec/blob/fc1677ba/pkg/models/watcher_auth_request.go
title: WatcherAuthRequest generated model
fetched: 2026-09-18
authority: source
ref: github.com/crowdsecurity/crowdsec@fc1677ba:pkg/models/watcher_auth_request.go
---

swagger:model WatcherAuthRequest.
MachineID *string `json:"machine_id"` required.
Password *strfmt.Password `json:"password"` required, format password.
Scenarios []string `json:"scenarios"` optional, "the list of scenarios enabled on the watcher".
Validate checks machine_id and password required only. No other JSON-tagged fields.
