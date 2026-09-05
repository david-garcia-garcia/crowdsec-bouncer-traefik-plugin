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

## propose (2026-09-05T07:48:50.000Z)
phase: propose
findings: none
fixed: none
skipped: logger close
qualify: qualified-with-gaps
change: crowdsec-connection-bouncer-split
pr: https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/6
head: 57b10f6f0048365485dc1ab6d3211d5b6fda4f1e

## implement (2026-09-05T08:23:22.919Z)
phase: implement
findings: none
fixed: reclaim CrowdsecConnection; isolated cache; dual-bouncer mock e2e; CI green on a72cb8c
skipped: logger OpenFile close (note large)
head: a72cb8c374fa227d27503352c19886bbe5888d91

## codereview (2026-09-05T08:29:39.778Z)
phase: codereview
findings: P3 11 hard Leave a trail / Name for the scope; 1 judgement Duplicated Code
fixed: version bump path, stale log prefixes, job comments, routeHandler local
skipped: decisionRemediation helper (judgement)
head: 7ae1d26582a9552669d0fdbffc9dd67ed297773c

## devdocsimpact (2026-09-05T08:33:14.680Z)
phase: devdocsimpact
findings: missing packets for plugin/reclaim/isolated cache/mock e2e; stale Redis keyPrefix
fixed: core_plugin_middleware, std_go_reclaim, core_cache_client, build_e2e_mock; updated core_cache_redis
skipped: none
head: 37e8d20d1acf58099a7b387b4e131352bbbe1857

## archive (2026-09-05T08:35:19.460Z)
phase: archive
findings: none
fixed: four spec ids synced to openspec/specs; change moved to archive/2026-09-05-crowdsec-connection-bouncer-split
skipped: none
head: 24a90906d053201a19aea0ab306906a72bfd9efc

## pullrequest (2026-09-05T08:44:54.022Z)
phase: pullrequest
findings: mock e2e failed once on 24a9090 (exit 2); retried with dual-bouncer poll + log dump
fixed: wait_for_status on dual-bouncer; print scenario logs on fail; ready title; CI green on 40c19d5
skipped: none
head: 40c19d59fd40077de70472eea216ed6c24c2614b

## pullrequest (2026-09-05T09:14:00.108Z)
phase: pullrequest
findings: Main Process failed on f4e5bea (revive unused t in Test_ClientCloseRedis)
fixed: drain Redis idle pools on CrowdsecConnection.Close; unused-parameter lint; CI green on f7f9ba0
skipped: logger OpenFile close; failed New without Close; in-flight ticker HTTP
head: f7f9ba024d6559f91996d372ce7b77b21ed06ee9
