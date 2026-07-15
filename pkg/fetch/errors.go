package fetch

import "errors"

var (
	ErrFetch      = errors.New("fetch failed")
	ErrInvalidURL = errors.New("invalid URL")
)
