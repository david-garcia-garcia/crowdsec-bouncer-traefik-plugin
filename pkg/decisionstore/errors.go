package decisionstore

import "errors"

// ErrMiss and ErrUnreachable are lookup sentinels. Callers use errors.Is.
var (
	ErrMiss        = errors.New("store:miss")
	ErrUnreachable = errors.New("store:unreachable")
)
