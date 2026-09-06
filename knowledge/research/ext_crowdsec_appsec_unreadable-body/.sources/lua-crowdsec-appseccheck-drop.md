---
ref: github.com/crowdsecurity/lua-cs-bouncer@59f3521e3918377fc1eb97d59a4056b6e9f5782f:lib/crowdsec.lua
title: AppSecCheck drop path
fetched: 2026-09-06
authority: source
---

local body, body_len, unreadable_body, close_body = get_body()
if unreadable_body and runtime.conf["APPSEC_DROP_UNREADABLE_BODY"] then
  ngx.log(ngx.WARN, "Dropping request because body is unreadable and APPSEC_DROP_UNREADABLE_BODY is enabled")
  return false, runtime.conf["FALLBACK_REMEDIATION"], ngx.HTTP_FORBIDDEN, {}, nil
end

Default method = "GET". If body_len > 0 then method = "POST" and body forwarded.
