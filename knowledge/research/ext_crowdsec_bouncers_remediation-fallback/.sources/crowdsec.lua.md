---
url: https://github.com/crowdsecurity/lua-cs-bouncer/blob/4aad1dfa653d9d96fb5c0114ae930eb2353214c8/lib/crowdsec.lua
title: lua-cs-bouncer request handler
fetched: 2026-11-14
authority: source
ref: github.com/crowdsecurity/lua-cs-bouncer@4aad1dfa653d9d96fb5c0114ae930eb2353214c8:lib/crowdsec.lua
---

L119: runtime.fallback = runtime.conf["FALLBACK_REMEDIATION"].

L906-916 (request time, after LAPI cache/live lookup and AppSec):
  if runtime.fallback ~= "" then
    -- if we can't use captcha, fallback
    if remediation == "captcha" and captcha_ok == false then remediation = runtime.fallback end
    -- if remediation is not supported, fallback
    if remediation ~= "captcha" and remediation ~= "ban" and remediation ~= "challenge" then
      remediation = runtime.fallback
    end
  end

L918-967: if not ok -> "ban" => ban.apply; "challenge" => challenge.apply with AppSec body, or ERR "challenge remediation for '<ip>' but no response data, falling back to ban"; "captcha" (captcha_ok) => captcha flow. L967 falls through to ngx.exit(ngx.DECLINED) (pass).

Known types: ban, captcha, challenge. Everything else maps to FALLBACK_REMEDIATION at request time.
