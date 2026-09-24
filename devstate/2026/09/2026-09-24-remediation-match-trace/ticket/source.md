i need to improve debugging, i now get these messages:

time=2026-09-24T19:12:40.985Z level=TRACE msg=ServeHTTP component=CrowdsecBouncerTraefikPlugin traefikName=crowdsec-crowdsecfork@kubernetescrd ip=176.84.121.23 isTrusted=false
time=2026-09-24T19:12:40.985Z level=TRACE msg=ServeHTTP component=CrowdsecBouncerTraefikPlugin traefikName=crowdsec-crowdsecfork@kubernetescrd ip=176.84.121.23 cache=hit remediation=t

but it is not helpful. First, cache is not a thing anymore. Second, it does not help me interpret WHAT make this remediation trigger? seing the IP is ok, but if we are using scoped based remediations (headers, as, etc..) the values of those are also helpful.
