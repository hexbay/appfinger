package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/hexbay/appfinger/internal"
	"github.com/hexbay/appfinger/pkg/crawl"
	"github.com/hexbay/appfinger/pkg/external/customrules"
	"github.com/hexbay/appfinger/pkg/rule"
	"github.com/hexbay/appfinger/pkg/runner"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
)

const Version = "v0.3.4"

var Banner = fmt.Sprintf(`
______          %s             ________  __                                         
 /      \                     |        \|  \                                        
|  $$$$$$\  ______    ______  | $$$$$$$$ \$$ _______    ______    ______    ______  
| $$__| $$ /      \  /      \ | $$__    |  \|       \  /      \  /      \  /      \ 
| $$    $$|  $$$$$$\|  $$$$$$\| $$  \   | $$| $$$$$$$\|  $$$$$$\|  $$$$$$\|  $$$$$$\
| $$$$$$$$| $$  | $$| $$  | $$| $$$$$   | $$| $$  | $$| $$  | $$| $$    $$| $$   \$$
| $$  | $$| $$__/ $$| $$__/ $$| $$      | $$| $$  | $$| $$__| $$| $$$$$$$$| $$      
| $$  | $$| $$    $$| $$    $$| $$      | $$| $$  | $$ \$$    $$ \$$     \| $$      
 \$$   \$$| $$$$$$$ | $$$$$$$  \$$       \$$ \$$   \$$ _\$$$$$$$  \$$$$$$$ \$$      
          | $$      | $$                              |  \__| $$                    
          | $$      | $$                               \$$    $$                    
           \$$       \$$                                \$$$$$$                     
`, Version)

func main() {
	gologger.DefaultLogger.SetMaxLevel(levels.LevelWarning)
	options := internal.ParseOptions()
	if options.Debug {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)
	}
	if options.Version {
		gologger.Info().Msgf("AppFinger Version: %s", Version)
		return
	}
	if options.UpdateRule {
		customrules.DefaultProvider.Update(context.Background(), options.FingerHome)
		return
	}
	if options.Validate {
		// 严格校验：收集所有规则文件中的 YAML/Matcher 错误
		if errs, fatalErr := rule.ValidateRuleDirectory(options.FingerHome); fatalErr != nil {
			gologger.Error().Msgf("validate rules failed: %s", fatalErr.Error())
			os.Exit(1)
		} else if len(errs) > 0 {
			for _, e := range errs {
				gologger.Error().Msgf("validate error: %s", e.Error())
			}
			os.Exit(1)
		}

		// 如果严格校验通过，再按运行时逻辑加载一次规则，确保整体 Finger 可以正常建立
		manager := rule.GetRuleManager()
		if err := manager.LoadRules(options.FingerHome); err != nil {
			gologger.Error().Msgf("validate rules failed on load: %s", err.Error())
			os.Exit(1)
		}
		// 计算规则总数
		totalRules := 0
		for _, rules := range manager.GetFinger().Rules {
			totalRules += len(rules)
		}
		gologger.Info().Msgf("Validate success: loaded %d rule categories with %d total rules", len(manager.GetFinger().Rules), totalRules)
		return
	}
	crawlOptions := crawl.DefaultOption()
	crawlOptions.DebugReq = options.DebugReq
	crawlOptions.DebugResp = options.DebugResp
	crawlOptions.DisableIcon = options.DisableIcon
	crawlOptions.Timeout = time.Duration(options.Timeout) * time.Second
	crawlOptions.Proxy = options.Proxy
	spider := crawl.NewCrawler(crawlOptions)
	manager := rule.GetRuleManager()
	err := manager.LoadRules(options.FingerHome)
	if err != nil {
		gologger.Print().Msgf(err.Error())
		return
	}
	// 计算规则总数
	totalRules := 0
	for _, rules := range manager.GetFinger().Rules {
		totalRules += len(rules)
	}
	gologger.Info().Msgf("Loaded %d rule categories with %d total rules", len(manager.GetFinger().Rules), totalRules)
	// 将internal.Options转换为runner.Options
	runnerOptions := &runner.Options{
		// 输入相关
		Targets: options.URL,
		File:    options.UrlFile,
		Stdin:   options.Stdin,
		// 运行相关
		Threads:  options.Threads,
		Timeout:  options.Timeout,
		Verbose:  options.Debug,
		Silent:   false,
		RulePath: options.FingerHome,

		// 输出相关
		Output:    options.OutputFile,
		JSON:      options.OutputType == "json",
		NoColor:   false,
		OutputAll: true,
	}

	appRunner, err := runner.NewRunner(spider, manager, runnerOptions)
	if err != nil {
		gologger.Print().Msgf(err.Error())
		return
	}
	err = appRunner.Enumerate()
	if err != nil {
		gologger.Error().Msgf(err.Error())
		return
	}
}
