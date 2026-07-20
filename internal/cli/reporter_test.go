package cli

import (
	"bytes"
	"encoding/json"
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
			IconHash:   -127886975,
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
	assert.Contains(t, line, "icon_hash=-127886975")
	assert.Contains(t, line, "tech=Typo3, Ubuntu(version=22.04)")
	assert.Contains(t, line, "time=1.234s")
}

func TestReporterJSONIncludesIconHash(t *testing.T) {
	var buf bytes.Buffer
	reporter, err := NewReporter(ReporterConfig{Writer: &buf, JSON: true})
	assert.NoError(t, err)

	reporter.Write("http://example.test", &scanner.Result{
		Banner:   &fetch.Banner{IconHash: -127886975},
		Duration: time.Second,
	}, nil)

	var output map[string]any
	assert.NoError(t, json.Unmarshal(buf.Bytes(), &output))
	assert.Equal(t, float64(-127886975), output["icon_hash"])
}
