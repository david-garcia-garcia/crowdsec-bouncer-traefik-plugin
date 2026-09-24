# Test coverage

1. [judgement] Assertion does not prove the job — `pkg/bouncer/zzz_debug_attrs_test.go:200` — remediating TRACE with Country mapped and header missing only asserts `"Country"` is absent; DestBranch store-hit TRACE also lacks Country, so reverting `withPresentScopes` leaves this test green
   Quote:
      ```
      func withPresentScopes(args []any, scopes map[string]string) []any {
      	if len(scopes) == 0 {
      		return args
      	}
      logger.Trace(b.log, "ServeHTTP", withPresentScopes([]any{"ip", req.remoteIP, "remediation", kind}, scopes)...)
      TestHunt_ServeHTTPTraceRemediatingOmitsMissingHeaders maps only Country, sets no header, asserts !strings.Contains(record, `"Country"`)
      ```
   Fix: Assert a present sibling scope in `scopes` and omit Country so revert of the group fails
   Status: skipped
   Argument: judgement; sibling present-scopes test already fails on revert; not applied unattended.
