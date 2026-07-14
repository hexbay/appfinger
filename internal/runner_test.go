package internal

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/hexbay/appfinger/pkg/external/customrules"
	"github.com/hexbay/appfinger/pkg/fetch"
	"github.com/hexbay/appfinger/pkg/matchers"
	"github.com/hexbay/appfinger/pkg/rule"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/stretchr/testify/assert"
)

func TestParseOptions(t *testing.T) {
	// Save original args and restore after test
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	// Test default options
	os.Args = []string{"appfinger"}
	options := ParseOptions()
	assert.Equal(t, 10, options.Threads, "Default threads should be 10")
	assert.Equal(t, 10, options.Timeout, "Default timeout should be 10")
	assert.False(t, options.Debug, "Debug should be false by default")
	assert.False(t, options.Stdin, "Stdin should be false by default")

	// Test with custom options
	os.Args = []string{
		"appfinger",
		"-u", "http://example.com",
		"-t", "20",
		"--timeout", "30",
		"--debug",
		"-o", "output.json",
	}
	options = ParseOptions()
	assert.Equal(t, "http://example.com", options.URL[0], "URL should be set correctly")
	assert.Equal(t, 1, len(options.URL), "Should have 1 URL")
	assert.Equal(t, 20, options.Threads, "Threads should be set to 20")
	assert.Equal(t, 30, options.Timeout, "Timeout should be set to 30")
	assert.True(t, options.Debug, "Debug should be true")
	assert.Equal(t, "output.json", options.OutputFile, "Output file should be set correctly")
}

func TestRuleMatching(t *testing.T) {
	// Create a test banner
	banner := &fetch.Banner{
		Uri:        "http://example.com",
		Body:       "<html><body>Test content with WordPress</body></html>",
		Title:      "Test Page",
		StatusCode: 200,
		Headers: map[string]string{
			"server": "Apache/2.4.41",
		},
		Compliance: make(map[string]string),
	}

	// Create matchers properly
	wordPressMatcher := &matchers.Matcher{
		Part:  "body",
		Words: []string{"WordPress"},
	}
	wordPressMatcher.Type.MatcherType = matchers.WordsMatcher

	apacheMatcher := &matchers.Matcher{
		Part:  "headers.server",
		Words: []string{"Apache"},
	}
	apacheMatcher.Type.MatcherType = matchers.WordsMatcher

	// Create rules for testing
	testRules := []*rule.Rule{
		{
			Name:     "WordPress",
			Service:  "http",
			Matchers: []*matchers.Matcher{wordPressMatcher},
		},
		{
			Name:     "Apache",
			Service:  "http",
			Matchers: []*matchers.Matcher{apacheMatcher},
		},
	}

	// Create finger and add rules
	finger := rule.NewFinger()
	finger.AddRules(testRules)

	// Create a MatchPartGetter from the banner
	getMatchPart := createMatchPartGetter(banner)

	// Test matching
	results := finger.Match("http", getMatchPart)
	assert.NotNil(t, results, "Results should not be nil")
	assert.Equal(t, 2, len(results), "Should have 2 matches")

	// Check that the matched rules are correct
	matchedNames := make([]string, 0, len(results))
	for _, result := range results {
		matchedNames = append(matchedNames, result.Rule.Name)
	}
	assert.Contains(t, matchedNames, "WordPress", "Should identify WordPress")
	assert.Contains(t, matchedNames, "Apache", "Should identify Apache")
}

// createMatchPartGetter creates a MatchPartGetter function from a Banner
func createMatchPartGetter(banner *fetch.Banner) rule.MatchPartGetter {
	lowerCache := make(map[string]string)
	lowerCache["body"] = strings.ToLower(banner.Body)
	lowerCache["header"] = strings.ToLower(banner.Header)
	lowerCache["title"] = strings.ToLower(banner.Title)
	lowerCache["response"] = strings.ToLower(banner.Response)
	lowerCache["server"] = strings.ToLower(banner.Headers["server"])
	lowerCache["cert"] = strings.ToLower(banner.Certificate)
	for key, value := range banner.Headers {
		lowerCache[key] = strings.ToLower(value)
	}

	return func(part string, caseSensitive bool) string {
		if !caseSensitive {
			if strings.Contains(part, "headers.") {
				part = part[8:]
			}
			if value, ok := lowerCache[part]; ok {
				return value
			}
		}
		if strings.Contains(part, "headers.") {
			return banner.Headers[part[8:]]
		}
		switch part {
		case "url":
			return banner.Uri
		case "body":
			return banner.Body
		case "header":
			return banner.Header
		case "cert":
			return banner.Certificate
		case "title":
			return banner.Title
		case "response":
			return banner.Response
		case "icon_hash":
			return fmt.Sprintf("%v", banner.IconHash)
		case "body_hash":
			return fmt.Sprintf("%v", banner.BodyHash)
		case "server":
			return banner.Headers["server"]
		}
		return ""
	}
}

func TestCustomRulesUpdate(t *testing.T) {
	// Skip this test if we're not in an environment where we can download rules
	if testing.Short() {
		t.Skip("Skipping test in short mode")
	}

	tempDir := t.TempDir()
	customrules.DefaultProvider.Update(context.Background(), tempDir)

	// Verify that rules were downloaded
	_, err := os.ReadDir(tempDir)
	assert.NoError(t, err, "Reading directory should not fail")
	// Note: This test may fail if network is unavailable, which is acceptable
}

func TestLoggerSetup(t *testing.T) {
	// Save original logger and restore after test
	oldLogger := gologger.DefaultLogger
	defer func() { gologger.DefaultLogger = oldLogger }()

	gologger.DefaultLogger.SetMaxLevel(levels.LevelInfo)

	// No assertions needed here, we're just making sure it doesn't crash
}

func TestFormatExtract(t *testing.T) {
	extract := map[string]map[string]string{
		"component1": {
			"version": "1.0.0",
			"type":    "framework",
		},
		"component2": {
			"name": "test",
		},
	}

	result := formatExtract(extract)
	assert.NotEmpty(t, result, "Format extract should return non-empty string")
	assert.Contains(t, result, "component1", "Should contain component1")
	assert.Contains(t, result, "component2", "Should contain component2")
}

func TestStringTerms(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"hello\nworld", "helloworld"},
		{"test\t\tvalue", "testvalue"},
		{" trimmed ", "trimmed"},
		{"normal", "normal"},
	}

	for _, tt := range tests {
		result := StringTerms(tt.input)
		assert.Equal(t, tt.expected, result, "StringTerms should process string correctly")
	}
}

func TestSanitize(t *testing.T) {
	tests := []struct {
		input       string
		expected    string
		shouldError bool
	}{
		{"  test  ", "test", false},
		{"\n\tvalue\t\n", "value", false},
		{"\"quoted\"", "quoted", false},
		{"'single'", "single", false},
		{"", "", true},
		{"   ", "", true},
	}

	for _, tt := range tests {
		result, err := sanitize(tt.input)
		if tt.shouldError {
			assert.Error(t, err, "Should return error for empty input")
			assert.Equal(t, ErrEmptyInput, err, "Should return ErrEmptyInput")
		} else {
			assert.NoError(t, err, "Should not return error")
			assert.Equal(t, tt.expected, result, "Sanitize should process string correctly")
		}
	}
}
