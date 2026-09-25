# Scope

1. [judgement] Scope vs Requirements — `requirement.md` — 2026-09-25-request-bypass-rules Desired compile stores an uppercased method (case-insensitive HTTP method, omit = any); `pkg/httprule` compiles `method` as case-sensitive unanchored RE2 with optional `!`
   Fix: Compile method as an uppercased token or empty, and match `req.Method` case-insensitively
   Status: skipped
   Quote:
      ```
      Compile once: uppercased method or empty, compiled path regexp or nil, canonical header names, cookie names.
      ```
   Argument: judgement; taken reshape already records method as case-sensitive RE2.

2. [judgement] Scope vs Requirements — `requirement.md` — 2026-09-25-request-bypass-rules Desired rejects a fully empty rule including method-only; `httprule.New` accepts method-only (`{Method: "^OPTIONS$"}`) and configuration tests pass that case
   Fix: Reject rules with no path, no headers, and no cookies (method-only or nothing) at `httprule.New`
   Status: skipped
   Quote:
      ```
      Fully empty rule (no path, no headers, no cookies — method-only or nothing) fails plugin construction.
      ```
   Note:
      ```
      Problem also says a block with no path, headers, or cookies matches every request of that method, then must reject that fully empty rule.
      ```
   Argument: judgement; taken reshape already records method-only rules as valid.
