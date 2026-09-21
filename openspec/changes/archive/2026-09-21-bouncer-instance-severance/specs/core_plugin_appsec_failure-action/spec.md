## ADDED Requirements

### Requirement: Missing named AppSec client uses AppSec failure action
When `appsecEnabled` is true and Peek of the named AppSec slot misses, the bouncing handler SHALL apply `bouncerAppsecFailureAction` the same way an AppSec listener error does.

#### Scenario: Subscribe miss bans by default
- **WHEN** a bouncing router has `appsecEnabled` true, `appsecInstance` `shared-waf`, empty AppSec failure action, and no Client is published
- **THEN** the request is remediated as a ban
