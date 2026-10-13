---
url: https://www.dragonflydb.io/docs/getting-started/docker
title: Install with Docker
fetched: 2026-09-05
authority: official
---

Linux: docker run --network=host --ulimit memlock=-1 docker.dragonflydb.io/dragonflydb/dragonfly

macOS and Windows: docker run -p 6379:6379 --ulimit memlock=-1 docker.dragonflydb.io/dragonflydb/dragonfly
(network=host does not work well on macOS.)

Responds to both http and redis requests out of the box. redis-cli to localhost:6379, or browser to http://localhost:6379.

Step 2 example: SET hello world; GET hello → "world".
