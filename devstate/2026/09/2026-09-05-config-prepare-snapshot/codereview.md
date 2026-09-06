# Code review
Fixed point: origin/master (2d4acf366cf91884967f91e87a54e7744d62078d)
Diff: git diff origin/master...HEAD -- . ':!devstate' ':!.cursor'

## Standards
1. [hard] Leave a trail — `plugin_test.go:95` — new test function has no succinct job comment
   → Add one line that `New` must leave Traefik’s Config pointer unchanged (mixed-case `LogLevel`, ban path alias stays off the caller)

## Spec
none

## Security
none

## Performance
none

## Dead
none

Standards: 1 finding, worst: Leave a trail at `plugin_test.go:95`
Spec: none
Security: none
Performance: none
Dead: none

## Applied
- Standards 1: added job comment on `TestNew_DoesNotMutateCallerConfig`

## Recorded and skipped
none.
