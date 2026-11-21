package lapi

import "time"

// remediationKindForTest keeps the kind and error of one LookupRemediation, for tests that check only the kind.
func remediationKindForTest(kind, _ string, _ uint16, _ time.Duration, err error) (string, error) {
	return kind, err
}

// lookupErrForTest keeps the error of one LookupRemediation, for tests that check only the error.
func lookupErrForTest(_, _ string, _ uint16, _ time.Duration, err error) error {
	return err
}

// liveLookupErrForTest keeps the error of one LiveLookup, for tests that check only the error.
func liveLookupErrForTest(_, _ string, _ time.Duration, err error) error {
	return err
}
