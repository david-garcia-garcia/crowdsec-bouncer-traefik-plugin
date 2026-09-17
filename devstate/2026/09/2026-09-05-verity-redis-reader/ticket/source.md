# Verify Redis readers are held by pointer

issue-slug: verity-redis-reader
issueHost: local
destBranch: master

## Caller spec

Purpose is to ENSURE we are not affected by this issue from another project. If we are not, we need to prove by adding a test case that ensure this does not happen to us.

Target branch is master.

Completion is when PR passes CI and delivery card updated in PR.

## Issue from another project (identified)

https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/381

Title: Bump simpleredis to the pooled release and keep redis readers by pointer

Relevant ask (item 2): A pooled SimpleRedis holds a sync.Mutex, so pkg/cache/cache.go copying one by value into rc.readers trips go vet's copylocks check. readers must be []*simpleredis.SimpleRedis, nextReader returns rc.readers[idx], and Test_nextReader follows.

The copy-by-value pattern to avoid:

```go
for _, h := range readHosts {
    var r simpleredis.SimpleRedis
    r.Init(h, pass, database)
    rc.readers = append(rc.readers, r) // copies the lock
}
```
