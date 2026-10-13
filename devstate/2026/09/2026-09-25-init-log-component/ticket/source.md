# 2026-09-25-init-log-component

issueHost: local
issueRef: none

Log lines like these must become ONE line. All trusted IP ranges must be logged in one single log line:

time=2026-09-25T10:49:27.397Z level=DEBUG msg="IP network is trusted" component=CrowdsecBouncerTraefikPlugin traefikName=crowdsec-crowdsecfork@kubernetescrd network=127.0.0.1/32
time=2026-09-25T10:49:27.397Z level=DEBUG msg="IP network is trusted" component=CrowdsecBouncerTraefikPlugin traefikName=crowdsec-crowdsecfork@kubernetescrd network=::1/128
time=2026-09-25T10:49:27.397Z level=DEBUG msg="IP network is trusted" component=CrowdsecBouncerTraefikPlugin traefikName=crowdsec-crowdsecfork@kubernetescrd network=10.0.0.0/8
time=2026-09-25T10:49:27.397Z level=DEBUG msg="IP network is trusted" component=CrowdsecBouncerTraefikPlugin traefikName=crowdsec-crowdsecfork@kubernetescrd network=172.16.0.0/12
time=2026-09-25T10:49:27.397Z level=DEBUG msg="IP network is trusted" component=CrowdsecBouncerTraefikPlugin traefikName=crowdsec-crowdsecfork@kubernetescrd network=192.168.0.0/16

Ideally as part of DEBUG msg="Bouncer initialized" component=CrowdsecBouncerTraefikPlugin traefikName=crowdsec-crowdsecfork@kubernetescrd, i.e. when we initialize the bouncer we emit a debug message which helps us know how it is configured (in this case the trusted networks).

ALSO, rename the component we are using: component=CrowdsecBouncerTraefikPlugin to something shorter like CrowdsecBounder.
