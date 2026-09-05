# Review journal

## prepare (2026-09-05T06:53:07.300Z)
phase: prepare
findings: none
fixed: none
skipped: none
qualify: qualified-with-gaps
pr: https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/6
head: 99fb8b11e567b4d6d25e242b333373f2e078713e

## explore (2026-09-05T06:55:52.156Z)
phase: explore
findings: empty TestNew/stream tables; Windows logger FD leak in logging tests
fixed: none
skipped: logger close; keyed connections; .traefik.yml import move
head: 67a304af4adaa0cf48997d9d459876a9dbee7e54

## explore (2026-09-05T07:01:57.287Z)
phase: explore
findings: New discards Traefik ctx; sync.Once was wrong vs sister reclaim
fixed: explore now uses pkg/reclaim for CrowdsecConnection; key assumed connection-field hash
skipped: WAF name+full-config key (would split tickers per alias)
head: 0c87fadfb590610e13ddf3bff0e761d62c8cf972
