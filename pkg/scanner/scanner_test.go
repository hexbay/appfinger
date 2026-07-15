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
	manager, err := rule.NewManager(rulesDir)
	require.NoError(t, err)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("demo")) }))
	defer ts.Close()
	fetcher, err := fetch.NewFetcher(fetch.DefaultOption())
	require.NoError(t, err)
	s, err := New(Config{Fetcher: fetcher, RuleProvider: manager})
	require.NoError(t, err)
	result, err := s.Scan(context.Background(), ts.URL)
	require.NoError(t, err)
	require.Len(t, result.Components, 1)
	require.Equal(t, "Demo", result.Components[0].Name)
	require.NotZero(t, result.Duration)
}

func TestScannerUsesLatestRulesSnapshotAfterReload(t *testing.T) {
	rulesDir := t.TempDir()
	rulePath := rulesDir + "/demo.yaml"
	writeRules := func(name string) {
		ruleFile := []byte("- name: " + name + "\n  service: http\n  matchers:\n    - type: word\n      words: [demo]\n      part: body\n")
		require.NoError(t, os.WriteFile(rulePath, ruleFile, 0644))
	}
	writeRules("BeforeReload")

	manager, err := rule.NewManager(rulesDir)
	require.NoError(t, err)
	fetcher, err := fetch.NewFetcher(fetch.DefaultOption())
	require.NoError(t, err)
	s, err := New(Config{Fetcher: fetcher, RuleProvider: manager})
	require.NoError(t, err)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("demo")) }))
	defer ts.Close()

	before, err := s.Scan(context.Background(), ts.URL)
	require.NoError(t, err)
	require.Equal(t, "BeforeReload", before.Components[0].Name)

	writeRules("AfterReload")
	require.NoError(t, manager.ReloadRules())

	after, err := s.Scan(context.Background(), ts.URL)
	require.NoError(t, err)
	require.Equal(t, "AfterReload", after.Components[0].Name)

	require.NoError(t, os.WriteFile(rulePath, []byte("- name: Invalid\n  matchers:\n    - type: word\n      words: [demo]\n      part: unsupported\n"), 0644))
	require.Error(t, manager.ReloadRules())

	lastKnownGood, err := s.Scan(context.Background(), ts.URL)
	require.NoError(t, err)
	require.Equal(t, "AfterReload", lastKnownGood.Components[0].Name)
}
