# Issues

- [ ] note large  OPEN PR #18 identity `decisionScopeHeaders` splitter → fail-on-conflict on the same LAPI URL+key
  Why: different scopes still share one LAPI `stream_cursor`. Two pollers steal deltas. Isolation already uses `BOUNCER_KEY_TRAEFIK_SCOPES`.
- [ ] note large  real e2e file-provider reclaim vs settings-change (`tests/e2e/real`)
  Why: needs a second LAPI bouncer key, file-provider watch, and 30s CrowdsecConnection grace. Unit tests cover Sleep/Wake and snapshot replace; this apply did not add a Docker Pester case.
