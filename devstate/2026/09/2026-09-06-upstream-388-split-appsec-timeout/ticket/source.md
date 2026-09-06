# [FEATURE] Split HTTPTimeoutSeconds into separate LAPI and Appsec timeouts

**Is your feature request related to a problem? Please describe.** 🐛

The `HTTPTimeoutSeconds` settings governs two quite different things :
- **The LAPI stream pull**: in stream mode, the pull of the initial decision set (in my tests, ~2MB pull). This can take some time, so we want this to be **long**.
- **Appsec** : the call that runs on every requests, very fast. If appsec is unreachable, each request wait a full timeout before proceeding, so we want this one to be **short**.

On my production environment, I want crowdsec to be non-critical, ie. if crowdsec is down for some reason, I get an alert but requests are not blocked. My issue is when Appsec is unreachable, this `HTTPTimeoutSeconds` gets added to **every requests**, which makes the environment unusable if too long. 

**Describe the solution you'd like** ✨
I think adding a different setting, like `AppsecTimeoutSeconds` (defaulting so `HTTPTimeoutSeconds` if not set) would allow setting different values here. 
Also I think setting the timeout in seconds is quite coarse, allowing to set milliseconds would be better (appsec requests take a few milliseconds only in my tests).
