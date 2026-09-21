---
url: https://github.com/dragonflydb/dragonfly/blob/e94300e6990093ec093cfb00d60c2e77ea4907e4/contrib/docker/docker-compose.yml
title: contrib/docker/docker-compose.yml
fetched: 2026-09-05
authority: source
ref: github.com/dragonflydb/dragonfly@e94300e6990093ec093cfb00d60c2e77ea4907e4:contrib/docker/docker-compose.yml
---

service dragonfly:
  image: docker.dragonflydb.io/dragonflydb/dragonfly
  ulimits.memlock: -1
  ports: 6379:6379
  volume /data
Untagged image (Compose default = latest).
