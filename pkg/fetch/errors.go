package fetch

import (
	"errors"
	"fmt"
	"strings"
)

var (
	ErrFetch      = errors.New("fetch failed")
	ErrInvalidURL = errors.New("invalid URL")
)

type RedirectHop struct {
	From       string
	To         string
	StatusCode int
}

type RedirectError struct {
	Hops []RedirectHop
	Err  error
}

func (e *RedirectError) Error() string {
	if e == nil || e.Err == nil {
		return ""
	}
	if len(e.Hops) == 0 {
		return e.Err.Error()
	}
	parts := make([]string, 0, len(e.Hops))
	for _, hop := range e.Hops {
		parts = append(parts, fmt.Sprintf("%s [%d] -> %s", hop.From, hop.StatusCode, hop.To))
	}
	return fmt.Sprintf("redirect chain %s: %v", strings.Join(parts, "; "), e.Err)
}

func (e *RedirectError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}
