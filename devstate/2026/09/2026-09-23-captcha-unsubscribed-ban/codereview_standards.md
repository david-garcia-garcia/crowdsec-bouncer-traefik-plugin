# Standards

1. [hard] Leave a trail — `pkg/bouncer/bouncer.go:587` — edited comment still says HEAD captcha never gets the ban page and only ban kind reaches handleBanServeHTTP
   Fix: Say captcha kind serves a challenge only when this router subscribed and the client is usable; unsubscribed captcha kind WARNs then handleBanServeHTTP
   Quote:
      ```
      // captcha remediation gets the captcha challenge page, never the ban page. Only ban kind
      // reaches handleBanServeHTTP from here. Unsubscribed captcha kind WARNs
      // crowdsec bouncer captcha unsubscribed then bans.
      ```
   Status: done
   Argument: Rewrote handleRemediationServeHTTP comment: captcha kind challenges only when subscribed and the client is usable; unsubscribed captcha kind WARNs then handleBanServeHTTP.
