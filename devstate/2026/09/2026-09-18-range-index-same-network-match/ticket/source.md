Range-index upsert and delete identify a line by raw CIDR text (`pkg/decisionscope/range.go` upsertIndexCIDR `existing == cidr`, removeCIDRFromIndex `network == cidr`). Membership already uses net.ParseCIDR, so AddRange(10.1.2.0/8) then RemoveRange(10.0.0.0/8) leaves 10.1.2.3 banned. Hydrate already rebuilds the in-process trees from the blob after ApplyRangeBatch — do not change that. The leftover ban is because the blob line was not removed.

Focused fix only:
- In upsertIndexCIDR and removeCIDRFromIndex, parse both sides with net.ParseCIDR and treat them as the same line when masked IP and prefix match (IP.Equal + same mask ones/bits, or Mask.String()).
- Keep master's ApplyRangeBatch shape: one read, upsert loop, remove loop, Set/Delete. Keep the read-error contract: a failed GET (not CacheMiss) returns the error and MUST NOT write an empty/truncated blob.
- Persist the incoming CIDR text as today (do not rewrite lines to (*net.IPNet).String()).
- Do NOT add: indexNetworkID, collapseRangeUpserts, hasParseableIndexCIDR early-return, dual identity helpers, sweep-rewrite of unrelated leftover spellings, metrics slot key changes, bare-IP host-prefix work, IPv4-mapped persist work.
- One small helper for the same-network compare is fine if it stays next to the two loops.

Tests: AddRange(10.1.2.0/8) then RemoveRange(10.0.0.0/8) clears membership for 10.1.2.3. Keep existing ApplyRangeBatch unread-base tests passing. Bound the ask to this comparison only.
