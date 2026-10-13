# Nitpicks

1. [hard] Name for the scope — `pkg/bouncer/bouncer.go:369` — `compiled` is the producer’s transform suffix; this body only MatchStrings the exclude regex
   Quote:
      ```
      func excludedBy(compiled *regexp.Regexp, httpReq *http.Request) bool {
      	return compiled != nil && compiled.MatchString(excludeMatchString(httpReq))
      }
      ```
   Fix: Rename to `excludeRegex` (the role this body uses; same stem as the Bouncer fields)
   Status: done
   Argument: Renamed `excludedBy` parameter `compiled` to `excludeRegex`.
2. [hard] Name for the scope — `pkg/configuration/configuration.go:203` — parameter `s` is a placeholder; the body immediately assigns a second name `pattern` after trim (not a new job)
   Quote:
      ```
      func CompileExcludeRegex(s string) (*regexp.Regexp, error) {
      	pattern := strings.TrimSpace(s)
      	if pattern == "" {
      		return nil, nil //nolint:nilnil // empty after trim is off, not a failure
      	}
      	return regexp.Compile(pattern)
      }
      ```
   Fix: Name the parameter `pattern`; keep that stem after trim (`pattern = strings.TrimSpace(pattern)`)
   Status: done
   Argument: Renamed `CompileExcludeRegex` parameter `s` to `pattern`; trim keeps that stem.
