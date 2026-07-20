package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/hexbay/appfinger/pkg/scanner"
)

type ReporterConfig struct {
	Writer io.Writer
	JSON   bool
}
type Reporter struct {
	writer io.Writer
	file   *os.File
	json   bool
	mu     sync.Mutex
}

func NewReporter(config ReporterConfig) (*Reporter, error) {
	if config.Writer == nil {
		config.Writer = os.Stdout
	}
	return &Reporter{writer: config.Writer, json: config.JSON}, nil
}
func NewFileReporter(filename string, jsonOutput bool) (*Reporter, error) {
	f, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, err
	}
	r, _ := NewReporter(ReporterConfig{Writer: f, JSON: jsonOutput})
	r.file = f
	return r, nil
}
func (r *Reporter) Write(target string, result *scanner.Result, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err != nil {
		_, _ = fmt.Fprintf(r.writer, "%s\terror=%v\n", target, err)
		return
	}
	if r.json {
		_ = json.NewEncoder(r.writer).Encode(struct {
			URL        string              `json:"url"`
			IconHash   int32               `json:"icon_hash,omitempty"`
			Components []scanner.Component `json:"components,omitempty"`
			Duration   int64               `json:"duration_ns"`
		}{target, resultIconHash(result), result.Components, result.Duration.Nanoseconds()})
		return
	}
	_, _ = fmt.Fprintln(r.writer, formatTextResult(target, result))
}

func formatTextResult(target string, result *scanner.Result) string {
	if result == nil {
		return fmt.Sprintf("[unknown] %s", target)
	}
	status := "-"
	title := "-"
	finalURL := target
	iconHash := "-"
	if result.Banner != nil {
		if result.Banner.StatusCode > 0 {
			status = fmt.Sprint(result.Banner.StatusCode)
		}
		if result.Banner.Title != "" {
			title = result.Banner.Title
		}
		if result.Banner.Uri != "" {
			finalURL = result.Banner.Uri
		}
		if result.Banner.IconHash != 0 {
			iconHash = fmt.Sprint(result.Banner.IconHash)
		}
	}
	components := formatComponents(result.Components)
	if components == "" {
		components = "-"
	}
	return fmt.Sprintf("[FOUND] %s | final=%s | status=%s | title=%q | icon_hash=%s | tech=%s | time=%s",
		target,
		finalURL,
		status,
		title,
		iconHash,
		components,
		result.Duration.Round(time.Millisecond),
	)
}

func resultIconHash(result *scanner.Result) int32 {
	if result == nil || result.Banner == nil {
		return 0
	}
	return result.Banner.IconHash
}

func formatComponents(components []scanner.Component) string {
	if len(components) == 0 {
		return ""
	}
	parts := make([]string, 0, len(components))
	for _, component := range components {
		if len(component.Values) == 0 {
			parts = append(parts, component.Name)
			continue
		}
		keys := make([]string, 0, len(component.Values))
		for key := range component.Values {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		values := make([]string, 0, len(keys))
		for _, key := range keys {
			values = append(values, fmt.Sprintf("%s=%s", key, component.Values[key]))
		}
		parts = append(parts, fmt.Sprintf("%s(%s)", component.Name, strings.Join(values, ", ")))
	}
	return strings.Join(parts, ", ")
}
func (r *Reporter) Close() error {
	if r.file != nil {
		return r.file.Close()
	}
	return nil
}
