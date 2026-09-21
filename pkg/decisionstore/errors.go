package decisionstore

import "errors"

// ErrMiss is Redis GET of an absent key (RangeIndex). LookupRemediation of an
// empty merge is empty kind and nil error, not ErrMiss.
// ErrUnreachable is a lookup sentinel. Callers use errors.Is.
var (
	ErrMiss        = errors.New("store:miss")
	ErrUnreachable = errors.New("store:unreachable")
)
