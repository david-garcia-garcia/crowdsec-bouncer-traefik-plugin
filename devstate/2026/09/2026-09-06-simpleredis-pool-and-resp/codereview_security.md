# Security review
total: 1
pending: 0
completed: 1

## Item 1
Status: done
Argument: RESP bulk/array caps prevent hostile Redis from forcing unbounded allocations.
Finding: 16 MiB bulk and 4096 array limits address DoS vector from peer headers.
