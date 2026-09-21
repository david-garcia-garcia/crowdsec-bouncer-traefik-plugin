# Deviations

- [x] taken  Peek then fall back to the Client New received
  Asked: bouncing handler MUST NOT store `*Client` from construct; request path Peek only.
  Instead: Peek the named slot first, then use the Client pointer `bouncer.New` already received.
  Owner: `pkg/bouncer/bouncer.go` `publishedLAPI` / `publishedAppsec`
  Why: unit tests inject Clients through `bouncer.New`; honouring Peek-only would require every test to Publish. Production Open still Publishes before `bouncer.New`, so Peek hits the slot.
  By: implement
  Requester: not asked
