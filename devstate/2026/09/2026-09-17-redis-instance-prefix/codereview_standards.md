# Standards

1. [judgement] Duplicated Code — `pkg/configuration/configuration.go:624` and `pkg/lapi/instance.go:21` — both trim `RedisCacheInstanceID` before use
   → Keep validate-time trim for fail-fast; Resolve trim covers Prepare-before-Validate paths
   Status: skipped
   Argument: validate and Prepare ordering both need safe trim; not worth a shared helper in this delta.
