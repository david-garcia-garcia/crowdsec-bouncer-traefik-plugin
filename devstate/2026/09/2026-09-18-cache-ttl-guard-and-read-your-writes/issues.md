# Issues

- [ ] note large  `knowledge/debt/2026-09-18-swallowed-redis-set-failure-reads-as-allowed.md`
  Why: a failed Redis `SET` is logged and dropped, so a ban from the stream delta is never served and the poller still calls the tick a success.

- [ ] note large  `knowledge/debt/2026-09-18-cross-instance-replication-lag-on-shared-decisions.md`
  Why: the pin only covers writes this instance made, so an instance that lost the stream lease still reads another instance's fresh decisions from a lagging replica.
