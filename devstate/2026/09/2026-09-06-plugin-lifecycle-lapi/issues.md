# Issues

- [ ] note large  OPEN PR #18 identity `decisionScopeHeaders` splitter → fail-on-conflict on the same LAPI URL+key
  Why: different scopes still share one LAPI `stream_cursor`. Two pollers steal deltas. Isolation already uses `BOUNCER_KEY_TRAEFIK_SCOPES`.
