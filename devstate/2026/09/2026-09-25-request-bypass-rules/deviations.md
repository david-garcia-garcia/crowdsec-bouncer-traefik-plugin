# Deviations

- [x] taken  method is Go RE2; method-only rules are valid
  Asked: method is a case-insensitive HTTP method token; a block with no path, no headers, and no cookies (method-only or nothing) fails plugin construction.
  Instead: method is unanchored Go RE2 on `req.Method` with optional leading `!`; no silent case-fold and no forced `(?i)`. A method-only rule is valid. Construction fails only when path, headers, and cookies are absent AND method is any (omitted, empty, or a match-everything pattern such as `.*`).
  Owner: `pkg/httprule`
  Why: honouring an exact case-insensitive token would add a second match family beside path RE2; treating a set method predicate as fully empty would reject `method: ^OPTIONS$`. Human correction already resolved method as RE2 same family as path.
  By: propose
  Requester: confirmed
