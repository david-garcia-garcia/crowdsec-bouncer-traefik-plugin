# Separate LAPI vs AppSec packages

I want to properly separate the LAPI components vs the APPSEC components. Indeed we need a rename, because now everything is under "crowdsecconnection" package.

I believe we need crowdsecconnection package to be renamed to lapi and then move connection_appsec to it's own package.

LAPI (Local API) is the decisions/remediation side. none, live, stream, and alone are how this plugin talks to that: query per request, poll a stream, or (alone) talk to CAPI instead of a local LAPI. Keys are crowdsecLapi*.

AppSec is the HTTP WAF / application-security engine. Different host, key, TLS, body limit, failure action (crowdsecAppsec*). It inspects the request, not the decision list.

target branch is master
