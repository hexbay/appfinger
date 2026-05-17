package runner

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/hexbay/appfinger/pkg/crawl"
	"github.com/hexbay/appfinger/pkg/rule"
)

// Result 表示指纹识别结果
type Result struct {
	Banner     *crawl.Banner
	Components map[string]map[string]string
}

type ExecutorsPlugin struct {
	Plugin *rule.Plugin
	Banner *crawl.Banner
}

// OutputFields 输出字段
type OutputFields struct {
	URL     string                       `json:"url"`
	Extract map[string]map[string]string `json:"extract,omitempty"`
}

// Runner 负责协调爬虫和规则匹配的执行流程
type Runner struct {
	crawler     *crawl.Crawler
	ruleManager *rule.Manager
	options     *Options    // 运行时配置选项
	outputs     []io.Writer // 输出写入器
}

// NewRunnerWithOptions 从选项创建Runner实例
func NewRunnerWithOptions(options *Options) (*Runner, error) {
	// 如果没有提供选项，使用默认选项
	if options == nil {
		options = &DefaultOptions
	}

	// 初始化爬虫
	crawlerOptions := &crawl.Options{
		Timeout: time.Duration(options.Timeout) * time.Second,
	}
	crawler := crawl.NewCrawler(crawlerOptions)

	// 初始化规则管理器
	var ruleManager *rule.Manager
	if options.RulePath != "" {
		// 如果指定了规则库路径，使用指定路径创建规则管理器
		var err error
		ruleManager, err = rule.NewManagerWithPath(options.RulePath)
		if err != nil {
			return nil, fmt.Errorf("加载规则库失败: %v", err)
		}
	} else {
		// 否则使用默认规则管理器
		ruleManager = rule.GetRuleManager()
	}

	// 使用初始化后的crawler和ruleManager创建Runner
	return NewRunner(crawler, ruleManager, options)
}

// New 使用功能选项模式创建Runner实例
func New(opts ...OptionFunc) (*Runner, error) {
	// 创建构建器
	builder := NewBuilder()

	// 应用所有选项
	for _, opt := range opts {
		opt(builder)
	}

	// 构建Runner实例
	return builder.Build()
}

// NewRunner 从现有的crawler和ruleManager创建Runner实例
func NewRunner(crawler *crawl.Crawler, ruleManager *rule.Manager, options *Options) (*Runner, error) {
	// 如果没有提供选项，使用默认选项
	if options == nil {
		options = &DefaultOptions
	}
	// 初始化Runner
	runner := &Runner{
		crawler:     crawler,
		ruleManager: ruleManager,
		options:     options,
		outputs:     []io.Writer{},
	}

	// 如果指定了输出文件，初始化输出写入器
	if options.Output != "" {
		outputFile, err := os.OpenFile(options.Output, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return nil, fmt.Errorf("无法创建输出文件: %v", err)
		}
		runner.outputs = append(runner.outputs, outputFile)
	}
	// 如果没有设置回调函数，使用默认的控制台输出
	if options.Callback == nil {
		options.Callback = func(target string, result *Result) {
			// 如果不是静默模式，则输出到控制台
			if !options.Silent {
				out := formatConsole(target, result.Banner, result.Components)
				gologger.Print().Msg(out)
			}
			// 如果有输出文件，则写入文件
			for _, output := range runner.outputs {
				outFields := &OutputFields{
					URL:     target,
					Extract: result.Components,
				}
				var data []byte
				var err error
				if options.JSON {
					data, err = json.Marshal(outFields)
					if err != nil {
						gologger.Warning().Msgf("序列化输出失败: %v", err)
						continue
					}
				} else {
					// 简单文本格式
					data = []byte(fmt.Sprintf("%s\t%v\n", target, result.Components))
				}

				_, err = output.Write(append(data, '\n'))
				if err != nil {
					gologger.Warning().Msgf("写入输出文件失败: %v", err)
				}
			}
		}
	}

	return runner, nil
}

// NewRunnerCompat 向后兼容的NewRunner函数，用于支持现有代码
func NewRunnerCompat(crawler *crawl.Crawler, ruleManager *rule.Manager) *Runner {
	// 使用默认选项创建Runner
	runner, err := NewRunner(crawler, ruleManager, nil)
	if err != nil {
		// 在兼容模式下，如果出错，记录日志并返回一个空的Runner
		gologger.Warning().Msgf("创建Runner失败: %v", err)
		return &Runner{
			crawler:     crawler,
			ruleManager: ruleManager,
			options:     &DefaultOptions,
			outputs:     []io.Writer{},
		}
	}
	return runner
}

// NewDefaultRunner 创建默认的Runner实例
func NewDefaultRunner(options *crawl.Options, finger *rule.Finger) *Runner {
	crawler := crawl.NewCrawler(options)
	var ruleManager *rule.Manager
	if finger == nil {
		ruleManager = rule.GetRuleManager()
	}

	return &Runner{
		crawler:     crawler,
		ruleManager: ruleManager,
	}
}

// Scan 扫描URL
func (r *Runner) Scan(uri string) (*Result, error) {
	return r.ScanWithContext(context.Background(), uri)
}

// ScanWithContext 执行指纹识别流程
func (r *Runner) ScanWithContext(ctx context.Context, uri string) (*Result, error) {
	// 获取网站信息
	banners, err := r.crawler.GetBanners(ctx, uri)
	if err != nil {
		return nil, err
	}
	// 获取指纹库
	finger := r.ruleManager.GetFinger()
	// 最终结果
	results := make(map[string]map[string]string)
	// 对每个banner进行匹配
	matchResults, matchPlugins := r.matchBanners(finger, banners)
	results = MergeMaps(results, matchResults)
	// 特殊处理
	if _, ok := results["honeypot"]; ok {
		results = map[string]map[string]string{"honeypot": make(map[string]string)}
	}
	// 获取最后一个banner作为默认banner
	lastBanner := banners[len(banners)-1]
	// WordPress插件匹配
	if _, ok := results["Wordpress"]; ok {
		// 如果匹配到Wordpress，使用最后一个banner来匹配WordPress插件
		wpPlugins := MatchWpPlugin(lastBanner.Body)
		results = MergeMaps(wpPlugins, results)
	}
	// 最后再匹配插件
	if len(matchPlugins) > 0 {
		for _, executePlugin := range matchPlugins {
			pluginBanners, err := r.ExecuteWithPlugin(ctx, executePlugin.Banner.Uri, executePlugin.Plugin)
			if err != nil {
				gologger.Debug().Msgf("Execute With Plugin Error: %v", err)
				continue
			}
			// 对插件返回的banners进行匹配
			matchResults, _ = r.matchBanners(finger, pluginBanners)
			results = MergeMaps(results, matchResults)
			lastBanner = pluginBanners[len(pluginBanners)-1]
		}
	}
	return &Result{
		Banner:     lastBanner,
		Components: results,
	}, nil
}

// urlJoin 连接基础URL和路径
func urlJoin(baseURL, urlPath string) string {
	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		return baseURL
	}

	parsedURL.Path = path.Join(parsedURL.Path, urlPath)
	return parsedURL.String()
}

// ExecuteWithPlugin 使用插件执行额外请求
func (r *Runner) ExecuteWithPlugin(ctx context.Context, baseURL string, plugin *rule.Plugin) ([]*crawl.Banner, error) {
	gologger.Debug().Msgf("Execute with Plugin: %s", plugin.Path)
	newURL := urlJoin(baseURL, plugin.Path)
	banners, err := r.crawler.GetBanners(ctx, newURL)
	return banners, err
}

// Match 兼容旧版API的匹配方法
func (r *Runner) Match(uri string) (banner *crawl.Banner, m map[string]map[string]string, err error) {
	// 使用背景上下文，以便与旧API兼容
	ctx := context.Background()

	// 执行爬取
	banner, err = r.crawler.GetBanner(ctx, uri)
	if err != nil {
		return nil, nil, err
	}

	// 执行匹配
	result, err := r.ScanWithContext(ctx, uri)
	if err != nil {
		return banner, nil, err
	}

	return banner, result.Components, nil
}

// matchBanners 对一组banner进行匹配并返回结果和插件
func (r *Runner) matchBanners(finger *rule.Finger, banners []*crawl.Banner) (map[string]map[string]string, []ExecutorsPlugin) {
	var plugins = make([]ExecutorsPlugin, 0)
	var results = make(map[string]map[string]string)
	// 对每个banner进行匹配
	for _, banner := range banners {
		// 创建banner适配器
		getMatchPart := CreateMatchPartGetter(banner)
		// 执行匹配
		matchResults := finger.Match("http", getMatchPart)
		// 记录每个规则匹配到的banner和插件
		for _, matchResult := range matchResults {
			//	提取结果
			if matchResult.IsPlugin() {
				for _, plugin := range matchResult.Rule.Plugins {
					plugins = append(plugins, ExecutorsPlugin{Plugin: plugin, Banner: banner})
				}
			} else {
				results = MergeMaps(map[string]map[string]string{matchResult.Rule.Name: matchResult.Extracted}, results)
			}
		}
	}
	return results, plugins
}

// CreateMatchPartGetter 创建一个从banner中提取匹配部分的函数
func CreateMatchPartGetter(banner *crawl.Banner) rule.MatchPartGetter {
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
	return func(part string, _ bool) string {
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

// Enumerate 执行指纹识别任务
func (r *Runner) Enumerate() error {
	ctx := context.Background()
	if r.ruleManager == nil {
		return fmt.Errorf("rule Not Configuration")
	}
	// 获取指纹库
	finger := r.ruleManager.GetFinger()
	if finger == nil {
		return fmt.Errorf("finger Not Load")
	}
	// 如果有单个目标URL
	if r.options.Target != "" {
		// 直接扫描单个目标
		result, err := r.Scan(r.options.Target)
		if err != nil {
			return fmt.Errorf("scan %s Failed: %v", r.options.Target, err)
		}
		// 调用回调函数处理结果
		if r.options.Callback != nil {
			r.options.Callback(r.options.Target, result)
		}
		return nil
	}
	// 如果有多个目标URL列表
	if len(r.options.Targets) > 0 {
		reader := strings.NewReader(strings.Join(r.options.Targets, "\n"))
		return r.enumerateMultipleTargets(ctx, reader)
	}
	// 如果有目标文件
	if r.options.File != "" {
		f, err := os.Open(r.options.File)
		if err != nil {
			return fmt.Errorf("open Target File Error: %v", err)
		}
		defer f.Close()
		return r.enumerateMultipleTargets(ctx, f)
	}

	// 如果使用标准输入
	if r.options.Stdin {
		gologger.Info().Msgf("loading target from stdin...")
		return r.enumerateMultipleTargets(ctx, os.Stdin)
	}

	return fmt.Errorf("not set targets")
}

// enumerateMultipleTargets 扫描多个目标
func (r *Runner) enumerateMultipleTargets(ctx context.Context, reader io.Reader) error {
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		// 检查上下文是否已经被取消
		select {
		case <-ctx.Done():
			return ctx.Err() // 返回上下文取消的错误
		default:
			// 继续执行
		}

		target := scanner.Text()
		// 使用传入的上下文调用ScanWithContext方法
		result, err := r.ScanWithContext(ctx, target)
		if err != nil {
			gologger.Warning().Msgf("scan target %s failed: %v", target, err)
			continue
		}
		// 调用回调函数处理结果
		if r.options.Callback != nil {
			r.options.Callback(target, result)
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read targets failed: %v", err)
	}
	return nil
}

// MergeMaps 合并两个map
func MergeMaps(m1, m2 map[string]map[string]string) map[string]map[string]string {
	result := make(map[string]map[string]string)

	// 遍历第一个 map
	for key, value := range m1 {
		result[key] = value
	}

	// 遍历第二个 map
	for key, value := range m2 {
		// 如果键已存在，则根据需求选择合并或覆盖值
		// 这里选择覆盖
		result[key] = value
	}

	return result
}
