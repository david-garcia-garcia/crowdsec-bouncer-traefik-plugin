# Code review — Spec
Pin: origin/master...HEAD

## Findings

- [resolved] `core_plugin_decisions_scopes` carried "Lookup keys (client IP, `scope:value`,
  `range-index`) MUST NOT change" under "Remediation cache values may carry origin". The apply does
  change the spelling of the client-IP key, so that sentence was amended to scope it to key *shapes*
  and to point at the new requirement, rather than left to contradict the code.
  Argument: PR #34 shipped this change against that sentence unamended. Silently violating a live
  requirement is how the next reader loses.
- [resolved] "Ip decisions stay exact-address keys" was rewritten as "Ip decisions key on the
  canonical address" and now states the both-sides rule the ticket exists to enforce, plus the
  non-IP-scope exclusion.
