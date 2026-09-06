# Performance review
total: 1
pending: 0
completed: 1

## Item 1
Status: done
Argument: maxOpenConns bounds live sockets under Traefik concurrency spikes.
Finding: Fail-fast at cap prevents unbounded TCP growth previously possible when idle pool exhausted.
