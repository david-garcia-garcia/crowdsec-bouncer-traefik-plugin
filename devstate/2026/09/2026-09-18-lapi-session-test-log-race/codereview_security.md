# Security

none.

Test-only diff. No secret, no trust boundary, no new sink. The captured log text stays in process memory and is only read by the test that produced it; the tests already logged the same records to a buffer before this change.
