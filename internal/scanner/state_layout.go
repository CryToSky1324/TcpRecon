package scanner

import "errors"

const (
	stateScopeBucket    = "scope"
	stateBaselineBucket = "baseline"
)

var ErrInvalidStateScopeID = errors.New("invalid state scope ID")
