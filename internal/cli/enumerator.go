package cli

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/hexbay/appfinger/pkg/scanner"
)

type TargetConfig struct {
	Targets []string
	File    string
	Stdin   bool
	Workers int
}
type Enumerator struct {
	config  TargetConfig
	scanner *scanner.Scanner
}

func NewEnumerator(config TargetConfig, s *scanner.Scanner) (*Enumerator, error) {
	if s == nil {
		return nil, fmt.Errorf("enumerator scanner is required")
	}
	if config.Workers <= 0 {
		config.Workers = 1
	}
	return &Enumerator{config: config, scanner: s}, nil
}

func (e *Enumerator) Run(ctx context.Context, callback func(string, *scanner.Result, error)) error {
	if ctx == nil {
		ctx = context.Background()
	}
	reader, closeReader, err := e.input()
	if err != nil {
		return err
	}
	if closeReader != nil {
		defer closeReader()
	}
	jobs := make(chan string)
	var wg sync.WaitGroup
	for i := 0; i < e.config.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for target := range jobs {
				result, scanErr := e.scanner.Scan(ctx, target)
				if callback != nil {
					callback(target, result, scanErr)
				}
			}
		}()
	}
	s := bufio.NewScanner(reader)
	for s.Scan() {
		target := strings.TrimSpace(s.Text())
		if target == "" {
			continue
		}
		select {
		case jobs <- target:
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return ctx.Err()
		}
	}
	close(jobs)
	wg.Wait()
	if err := s.Err(); err != nil {
		return fmt.Errorf("read targets failed: %w", err)
	}
	return nil
}

func (e *Enumerator) input() (io.Reader, func(), error) {
	if len(e.config.Targets) > 0 {
		return strings.NewReader(strings.Join(e.config.Targets, "\n")), nil, nil
	}
	if e.config.File != "" {
		f, err := os.Open(e.config.File)
		return f, func() {
			if f != nil {
				_ = f.Close()
			}
		}, err
	}
	if e.config.Stdin {
		return os.Stdin, nil, nil
	}
	return nil, nil, fmt.Errorf("no targets configured")
}
