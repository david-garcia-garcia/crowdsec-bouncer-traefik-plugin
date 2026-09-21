Title: Serve captcha for bans from configured decision origins (upstream #369, per-list)

Adopt what upstream developed in https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/369

`BanToCaptchaOrigins []string` — a `ban` decision whose origin is listed is stored with the captcha remediation instead of ban.

CAPI community blocklist and console-subscribed blocklists always deliver type `ban`; that type cannot be changed in CrowdSec console (community blocklist has no per-subscription remediation) or `profiles.yaml` (local alerts only). Upstream maps purely on `decision.Type`. A legitimate visitor on a shared community blocklist gets a hard 403 with no captcha path.

**Difference from upstream:** for CrowdSec `lists` origin, operators can differentiate by list. Config `lists` remaps every list-origin ban; config `lists:whateverlist` remaps only that list. This fork already rewrites stored origin via `MetricsOrigin` to `lists:` plus the decision scenario (list name).

Empty by default is a complete no-op. Unlisted origins stay ban. Without a captcha provider, a captcha value already falls back to ban rendering.

**Delivery card constraint (process, not product):** every sbs-dev-deliverreview card for this ticket MUST mention upstream PR https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/369 by URL.

When analyzing Current/Desired, ground in this tree (this fork already packs origin on decisions; do not assume the upstream plugin layout). Third-party CrowdSec LAPI origin/scenario/lists: `skill:sbs-dev-research:Investigate then write` if indexes show a gap. Do not invent extra product asks (no ticker-stop / Traefik restart fix unless the caller asked — they did not; put that in Out of scope if you see it).
