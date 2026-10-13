Add two public config settings, both Bouncer request policy (the package that reads them is the bouncer; they are not AppSec-client or LAPI-client reclaim-key knobs):

1. `bouncerAppsecExcludeRegex`
2. `bouncerLapiExcludeRegex`

Each setting is ONE regex (a single string, not a list). It is compiled once, not on every request. It is matched against a NORMALIZED incoming path of the form `{host}/path`:
- no scheme
- no port
- no query string

When the setting is empty, nothing is excluded for that leg.

The delivery card for this run must mention the upstream issue: https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/393 ("[FEATURE] Exclude host+path routes from the AppSec query" on maxlerebourg/crowdsec-bouncer-traefik-plugin). That issue is context for the card, not a second product requirement. Do not turn its location-list / EXCLUDE_LOCATION proposal into desired behavior. The desired behavior is the two regexes above.
