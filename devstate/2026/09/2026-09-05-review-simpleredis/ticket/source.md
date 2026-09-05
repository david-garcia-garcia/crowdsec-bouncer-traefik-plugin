# review-simpleredis

The purpose of this issue is ensure that the simpleredis component is as performant and resource efficient as possible, without introducing too much complexity or additional code length. To that purpose, I want to to review the official redis library for GO and also to have an OPUS subagent analyze the implementation looking for leaks, races and possible optimizations. You CAN use "unsafe" traefik middleware atrribute, which lets you some low level golang stdilb if needed. Only if the performance gains of doing so are worth it.

Focus is exclusively the redis communication layer.

Also consider test coverage gaps, and fill them.

Finished work is delivered PR with CI passing and updated delivery card.
