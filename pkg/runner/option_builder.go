package runner

import (
	"time"

	"github.com/hexbay/appfinger/pkg/fetch"
	"github.com/hexbay/appfinger/pkg/rule"
)

// OptionFunc 定义一个函数类型，用于设置Runner的选项
type OptionFunc func(*RunnerBuilder)

// RunnerBuilder 用于构建Runner实例的构建器
type RunnerBuilder struct {
	options     *Options
	fetcher     *fetch.Fetcher
	ruleManager *rule.Manager
}

// NewBuilder 创建一个新的Runner构建器
func NewBuilder() *RunnerBuilder {
	return &RunnerBuilder{
		options: &DefaultOptions,
	}
}

// WithFetcher 设置自定义Fetcher。
func WithFetcher(fetcher *fetch.Fetcher) OptionFunc {
	return func(rb *RunnerBuilder) {
		rb.fetcher = fetcher
	}
}

// WithRuleManager 设置自定义规则管理器
func WithRuleManager(manager *rule.Manager) OptionFunc {
	return func(rb *RunnerBuilder) {
		rb.ruleManager = manager
	}
}

// WithThreads 设置并发线程数
func WithThreads(threads int) OptionFunc {
	return func(rb *RunnerBuilder) {
		rb.options.Threads = threads
	}
}

// WithTimeout 设置超时时间（秒）
func WithTimeout(timeout int) OptionFunc {
	return func(rb *RunnerBuilder) {
		rb.options.Timeout = timeout
	}
}

// WithVerbose 设置是否输出详细信息
func WithVerbose(verbose bool) OptionFunc {
	return func(rb *RunnerBuilder) {
		rb.options.Verbose = verbose
	}
}

// WithSilent 设置是否静默模式
func WithSilent(silent bool) OptionFunc {
	return func(rb *RunnerBuilder) {
		rb.options.Silent = silent
	}
}

// WithRulePath 设置规则库路径
func WithRulePath(path string) OptionFunc {
	return func(rb *RunnerBuilder) {
		rb.options.RulePath = path
	}
}

// WithOutput 设置输出文件路径
func WithOutput(output string) OptionFunc {
	return func(rb *RunnerBuilder) {
		rb.options.Output = output
	}
}

// WithJSONOutput 设置是否输出JSON格式
func WithJSONOutput(json bool) OptionFunc {
	return func(rb *RunnerBuilder) {
		rb.options.JSON = json
	}
}

// WithCallback 设置结果处理回调函数
func WithCallback(callback func(target string, result *Result)) OptionFunc {
	return func(rb *RunnerBuilder) {
		rb.options.Callback = callback
	}
}

// Build 构建Runner实例
func (rb *RunnerBuilder) Build() (*Runner, error) {
	// 如果没有提供Fetcher，创建默认Fetcher。
	if rb.fetcher == nil {
		fetchOptions := fetch.DefaultOption()
		if rb.options.Timeout > 0 {
			fetchOptions.Timeout = time.Duration(rb.options.Timeout) * time.Second
		}
		rb.fetcher = fetch.NewFetcher(fetchOptions)
	}

	// 如果没有提供规则管理器，使用默认规则管理器
	if rb.ruleManager == nil {
		rb.ruleManager = rule.GetRuleManager()
		// 如果设置了规则路径，加载规则
		if rb.options.RulePath != "" {
			err := rb.ruleManager.LoadRules(rb.options.RulePath)
			if err != nil {
				return nil, err
			}
		}
	}

	// 创建Runner实例
	return NewRunner(rb.fetcher, rb.ruleManager, rb.options)
}
