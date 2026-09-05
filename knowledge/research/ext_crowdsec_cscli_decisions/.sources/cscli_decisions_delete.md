---
url: https://docs.crowdsec.net/docs/v1.7/cscli/cscli_decisions_delete
title: cscli decisions delete (CrowdSec v1.7)
fetched: 2026-09-05
authority: official
---

Delete decisions.
Examples: cscli decisions delete -i 1.2.3.4; -r range; --id 42; --type captcha.
-i / --ip: Source ip (shorthand for --scope ip --value <IP>)
-t / --type: ban, captcha
--all: delete all decisions
No remove subcommand on this page; documented name is delete.
