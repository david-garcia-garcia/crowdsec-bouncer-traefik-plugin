---
url: https://github.com/crowdsecurity/crowdsec/blob/fc1677ba/pkg/models/localapi_swagger.yaml
title: LAPI swagger WatcherAuthRequest
fetched: 2026-09-18
authority: source
ref: github.com/crowdsecurity/crowdsec@fc1677ba:pkg/models/localapi_swagger.yaml
---

POST /watchers/login body WatcherAuthRequest. Required: machine_id, password.
WatcherAuthRequest properties: machine_id (string), password (string, format password), scenarios (array of strings, "the list of scenarios enabled on the watcher"). No other properties.
WatcherRegistrationRequest (not login) adds optional registration_token (minLength 32, maxLength 255).
WatcherAuthResponse: code (integer), expire (string), token (string).
