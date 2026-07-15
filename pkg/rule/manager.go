package rule

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hexbay/appfinger/pkg/external/customrules"
	"github.com/projectdiscovery/gologger"
)

// Manager owns a sequence of immutable rules snapshots for one rule directory.
type Manager struct {
	rulePath     string
	reloadMu     sync.Mutex
	ruleSet      atomic.Pointer[RuleSet]
	lastLoadTime atomic.Int64
}

// NewManager loads the initial immutable rules snapshot from path.
func NewManager(path string) (*Manager, error) {
	m := &Manager{rulePath: path}
	if err := m.ReloadRules(); err != nil {
		return nil, err
	}
	return m, nil
}

// LoadDefaultRules ensures the default rule repository exists and loads it.
func LoadDefaultRules(ctx context.Context) (*Manager, error) {
	rulePath, err := customrules.EnsureDefaultDirectory(ctx)
	if err != nil {
		return nil, err
	}
	return NewManager(rulePath)
}

// ReloadRules loads and publishes a new immutable rules snapshot. A failed
// reload leaves the last successfully loaded snapshot available to scanners.
func (m *Manager) ReloadRules() error {
	m.reloadMu.Lock()
	defer m.reloadMu.Unlock()

	validationErrors, err := ValidateRuleDirectory(m.rulePath)
	if err != nil {
		return fmt.Errorf("验证规则库失败: %w", err)
	}
	if len(validationErrors) > 0 {
		return fmt.Errorf("验证规则库失败: %w", errors.Join(validationErrors...))
	}

	ruleSet, err := ScanRuleDirectory(m.rulePath)
	if err != nil {
		return fmt.Errorf("加载规则库失败: %w", err)
	}
	m.ruleSet.Store(ruleSet)
	m.lastLoadTime.Store(time.Now().UnixNano())
	gologger.Info().Msgf("Loaded rules from: %s rules: %d", m.rulePath, ruleSet.CategoryCount())
	return nil
}

// Snapshot returns the latest immutable rules snapshot.
func (m *Manager) Snapshot() *RuleSet {
	return m.ruleSet.Load()
}

// GetLastLoadTime returns when the current snapshot was published.
func (m *Manager) GetLastLoadTime() time.Time {
	nanos := m.lastLoadTime.Load()
	if nanos == 0 {
		return time.Time{}
	}
	return time.Unix(0, nanos)
}

// IsLoaded reports whether a rules snapshot is available.
func (m *Manager) IsLoaded() bool {
	return m.Snapshot() != nil
}

// FindRuleByName returns the first source rule in a category, if present.
func (m *Manager) FindRuleByName(name string) *Rule {
	snapshot := m.Snapshot()
	if snapshot == nil {
		return nil
	}
	return snapshot.FirstRule(name)
}
