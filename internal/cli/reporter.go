package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"

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
			URL        string                       `json:"url"`
			Components map[string]map[string]string `json:"components,omitempty"`
		}{target, result.Components})
		return
	}
	_, _ = fmt.Fprintf(r.writer, "%s\t%v\n", target, result.Components)
}
func (r *Reporter) Close() error {
	if r.file != nil {
		return r.file.Close()
	}
	return nil
}
