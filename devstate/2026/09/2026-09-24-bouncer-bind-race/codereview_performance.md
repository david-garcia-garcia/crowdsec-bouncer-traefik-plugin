# Performance

1. [judgement] Extra Box allocation per publish — `pkg/bouncer/bouncer.go:178` — every bind update allocates a new `*reclaim.Box`; design accepted this; publish is rare vs ServeHTTP
   Fix: Leave as landed; do not add a pool unless measure shows publish pressure
   Status: skipped
   Argument: judgement; design accepted extra Box allocations; not applied unattended.
