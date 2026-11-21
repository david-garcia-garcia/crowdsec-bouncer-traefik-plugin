# Nitpicks

1. [hard] Clear conditions — `pkg/decisionstore/liveslot.go:72` — `if slot.DecisionEnd <= now` handles the unknown end (0) only because `elapsedNow()` never goes below `elapsedBias`; the reader must know the clock bias to see the "unknown" case the doc comment promises, while sibling `decisionEndFromDuration` in the same file names its unknown case
   Quote:
   ```
      // decisionLeft is the time left on this slot's decision at elapsed now. Zero when the end is unknown or past.
      func (slot LiveSlot) decisionLeft(now int32) time.Duration {
      	if slot.DecisionEnd <= now {
      		return 0
      	}
      	return time.Duration(slot.DecisionEnd-now) * time.Second
      }
   ```
   Fix: `if slot.DecisionEnd == 0 || slot.DecisionEnd <= now { return 0 }` (no behaviour change: the only caller, `memory.LookupRemediation`, passes `elapsedNow()` >= `elapsedBias`)
   Status: done
   Argument: `LiveSlot.decisionLeft` now guards `slot.DecisionEnd == 0 || slot.DecisionEnd <= now`; behaviour unchanged.
