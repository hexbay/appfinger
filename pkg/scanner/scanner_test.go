package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/hexbay/appfinger/pkg/fetch"
	"github.com/hexbay/appfinger/pkg/rule"
	"github.com/stretchr/testify/require"
)

func TestScannerReturnsStructuredResult(t *testing.T) {
	rulesDir := t.TempDir()
	ruleFile := []byte("- name: Demo\n  service: http\n  matchers:\n    - type: word\n      words: [demo]\n      part: body\n")
	require.NoError(t, os.WriteFile(rulesDir+"/demo.yaml", ruleFile, 0644))
	rules, err := rule.ScanRuleDirectory(rulesDir)
	require.NoError(t, err)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("demo")) }))
	defer ts.Close()
	s, err := New(Config{Fetcher: fetch.NewFetcher(fetch.DefaultOption()), Rules: rules})
	require.NoError(t, err)
	result, err := s.Scan(context.Background(), ts.URL)
	require.NoError(t, err)
	require.Len(t, result.Components, 1)
	require.Equal(t, "Demo", result.Components[0].Name)
	require.NotZero(t, result.Duration)
}
