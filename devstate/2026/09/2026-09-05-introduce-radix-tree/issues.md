# Issues

- [ ] note large  Range remediation still linear (`pkg/decisionscope.MatchRangeFromIndex`) → future radix that can store remediation per CIDR
  Why: this ticket forbids Range wiring. Geoblock `iplookup` is membership + prefixLen only; Range needs `cidr → ban|captcha` and ban-wins. Do not extend the helper with values in this change.
