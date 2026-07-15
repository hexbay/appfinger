package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/hexbay/appfinger/internal/cli"
	"github.com/hexbay/appfinger/pkg/external/customrules"
	"github.com/hexbay/appfinger/pkg/fetch"
	"github.com/hexbay/appfinger/pkg/rule"
	"github.com/hexbay/appfinger/pkg/scanner"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
)

const Version = "dev"

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
	options := cli.ParseOptions()
	if options.Debug {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)
	}
	if options.Version {
		gologger.Info().Msgf("AppFinger Version: %s", Version)
		return
	}
	if options.UpdateRule {
		if err := customrules.DefaultProvider.Update(context.Background(), options.FingerHome); err != nil {
			gologger.Error().Msgf("update rules failed: %s", err.Error())
			os.Exit(1)
		}
		return
	}
	if options.Validate {
		if err := ensureDefaultRules(context.Background(), options.FingerHome); err != nil {
			gologger.Error().Msgf("init default rules failed: %s", err.Error())
			os.Exit(1)
		}
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
		manager := rule.NewManager()
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
	fetchOptions := fetch.DefaultOption()
	fetchOptions.DebugReq = options.DebugReq
	fetchOptions.DebugResp = options.DebugResp
	fetchOptions.DisableIcon = options.DisableIcon
	fetchOptions.DisableJavaScript = options.DisableJavaScript
	fetchOptions.Timeout = time.Duration(options.Timeout) * time.Second
	fetchOptions.Proxy = options.Proxy
	fetcherClient := fetch.NewFetcher(fetchOptions)
	if err := ensureDefaultRules(context.Background(), options.FingerHome); err != nil {
		gologger.Error().Msgf("init default rules failed: %s", err.Error())
		os.Exit(1)
	}
	manager := rule.NewManager()
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
	appScanner, err := scanner.New(scanner.Config{Fetcher: fetcherClient, Rules: manager.GetFinger()})
	if err != nil {
		gologger.Print().Msgf(err.Error())
		return
	}
	var output *cli.Reporter
	if options.OutputFile != "" {
		output, err = cli.NewFileReporter(options.OutputFile, options.OutputType == "json")
	} else {
		output, err = cli.NewReporter(cli.ReporterConfig{JSON: options.OutputType == "json"})
	}
	if err != nil {
		gologger.Error().Msgf(err.Error())
		return
	}
	defer output.Close()
	enum, err := cli.NewEnumerator(cli.TargetConfig{Targets: options.URL, File: options.UrlFile, Stdin: options.Stdin, Workers: options.Threads}, appScanner)
	if err == nil {
		err = enum.Run(context.Background(), output.Write)
	}
	if err != nil {
		gologger.Error().Msgf(err.Error())
		return
	}
}

func ensureDefaultRules(ctx context.Context, rulesDir string) error {
	if filepath.Clean(rulesDir) != filepath.Clean(customrules.GetDefaultDirectory()) {
		return nil
	}
	return customrules.EnsureDirectory(ctx, rulesDir)
}
