---
ref: github.com/crowdsecurity/lua-cs-bouncer@59f3521e3918377fc1eb97d59a4056b6e9f5782f:lib/crowdsec.lua
title: get_body unreadable detection
fetched: 2026-09-06
authority: source
---

Comment: LUA module requires content-length to read body for HTTP 2/3; no workaround.

if ngx.req.http_version() >= 2 and ngx.var.http_content_length == nil then
  return nil, 0, METHODS_WITH_BODY[ngx.var.request_method] == true, nil
end

Third return value is unreadable_body flag.
