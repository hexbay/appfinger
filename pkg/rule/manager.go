package rule

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/hexbay/appfinger/pkg/external/customrules"
	"github.com/projectdiscovery/gologger"
)

// Manager 规则管理器，实现单例模式和热更新
type Manager struct {
	ruleSet      *RuleSet
	rulePath     string
	lastLoadTime time.Time
	mutex        sync.RWMutex
}

// NewManager 创建一个新的规则管理器实例
func NewManager() *Manager {
	return &Manager{}
}

// NewManagerWithPath 创建一个新的规则管理器实例并加载指定路径的规则
func NewManagerWithPath(path string) (*Manager, error) {
	m := &Manager{}
	err := m.LoadRules(path)
	return m, err
}

// LoadDefaultRules ensures the default rule repository exists and loads it.
func LoadDefaultRules(ctx context.Context) (*Manager, error) {
	rulePath, err := customrules.EnsureDefaultDirectory(ctx)
	if err != nil {
		return nil, err
	}
	return NewManagerWithPath(rulePath)
}

// LoadRules 加载规则库
func (m *Manager) LoadRules(path string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	// 加载规则
	ruleSet, err := ScanRuleDirectory(path)
	if err != nil {
		return fmt.Errorf("加载规则库失败: %v", err)
	}
	// 更新规则和路径
	m.ruleSet = ruleSet
	m.rulePath = path
	m.lastLoadTime = time.Now()
	gologger.Info().Msgf("Loaded rules from: %s rules: %d", path, len(m.ruleSet.Rules))
	return nil
}

// GetRuleSet returns the latest immutable rule snapshot.
func (m *Manager) GetRuleSet() *RuleSet {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return m.ruleSet
}

// ReloadRules 重新加载规则库
func (m *Manager) ReloadRules() error {
	if m.rulePath == "" {
		return fmt.Errorf("未设置规则库路径")
	}
	return m.LoadRules(m.rulePath)
}

// GetLastLoadTime 获取最后加载时间
func (m *Manager) GetLastLoadTime() time.Time {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return m.lastLoadTime
}

// IsLoaded 判断规则库是否已加载
func (m *Manager) IsLoaded() bool {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return m.ruleSet != nil
}

// FindRuleByName 根据名称查找规则
func (m *Manager) FindRuleByName(name string) *Rule {
	if !m.IsLoaded() {
		return nil
	}

	m.mutex.RLock()
	defer m.mutex.RUnlock()

	// 查找指定名称的规则
	if rules, ok := m.ruleSet.Rules[name]; ok && len(rules) > 0 {
		return rules[0] // 返回第一个匹配的规则
	}

	return nil
}
