package cli

import (
	"strings"
	"testing"
	"time"

	"github.com/hexbay/appfinger/pkg/fetch"
	"github.com/hexbay/appfinger/pkg/scanner"
	"github.com/stretchr/testify/assert"
)

func TestFormatTextResult(t *testing.T) {
	result := &scanner.Result{
		Banner: &fetch.Banner{
			Uri:        "https://example.test/final",
			StatusCode: 200,
			Title:      "Example App",
		},
		Components: []scanner.Component{
			{Name: "Typo3"},
			{Name: "Ubuntu", Values: map[string]string{"version": "22.04"}},
		},
		Duration: 1234 * time.Millisecond,
	}

	line := formatTextResult("http://example.test", result)

	assert.True(t, strings.HasPrefix(line, "[FOUND] http://example.test | "))
	assert.Contains(t, line, "final=https://example.test/final")
	assert.Contains(t, line, "status=200")
	assert.Contains(t, line, `title="Example App"`)
	assert.Contains(t, line, "tech=Typo3, Ubuntu(version=22.04)")
	assert.Contains(t, line, "time=1.234s")
}
