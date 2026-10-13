# 2026-09-23-captcha-unsubscribed-ban

issueHost: local
issueRef: none

When the bouncer is not subscribed to a captcha provider, yet it receives the signal to do a captcha ban, it should degrade to BAN plus emit a log message in WARN indicating that the captcha could not be served due to a misconfiguration.
