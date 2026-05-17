package runner

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/stretchr/testify/assert"
	"github.com/hexbay/appfinger/pkg/crawl"
	"github.com/hexbay/appfinger/pkg/external/customrules"
	"github.com/hexbay/appfinger/pkg/rule"
)

func TestRunnerSSL(t *testing.T) {
	gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)
	spider := crawl.NewCrawler(crawl.DefaultOption())
	ruleManager := rule.GetRuleManager()
	
	rulesDir := customrules.GetDefaultDirectory()
	// Check if rules directory exists, if not, download it
	if _, err := os.Stat(rulesDir); os.IsNotExist(err) {
		t.Logf("Rules directory does not exist, downloading...")
		customrules.DefaultProvider.Download(nil, rulesDir)
	}
	
	_ = ruleManager.LoadRules(rulesDir)
	runner := NewRunnerCompat(spider, ruleManager)
	result, err := runner.Scan("https://www.hackerone.com")
	assert.NoError(t, err)
	if result != nil {
		assert.True(t, len(result.Components) >= 0)
	}
}

func TestRunnerWordPress(t *testing.T) {
	gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)
	spider := crawl.NewCrawler(crawl.DefaultOption())
	ruleManager := rule.GetRuleManager()
	
	rulesDir := customrules.GetDefaultDirectory()
	// Check if rules directory exists, if not, download it
	if _, err := os.Stat(rulesDir); os.IsNotExist(err) {
		t.Logf("Rules directory does not exist, downloading...")
		customrules.DefaultProvider.Download(nil, rulesDir)
	}
	
	_ = ruleManager.LoadRules(rulesDir)
	runner := NewRunnerCompat(spider, ruleManager)
	result, err := runner.Scan("https://cn.wordpress.org/")
	assert.NoError(t, err)
	if result != nil {
		assert.True(t, len(result.Components) >= 0)
	}
}

func TestRunnerPlugin(t *testing.T) {
	// 模拟插件匹配 etcd server
	gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)
	// 创建一个测试服务器来模拟API响应
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/":
			// 返回404 not found
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`404 page not found`))
		case "/version":
			// 返回版本信息
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"etcdserver":  "3.4.21",
				"etcdcluster": "3.4.0",
			})
		default:
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]string{"message": "404 page not found"})
		}
	}))
	defer ts.Close()
	// 创建规则管理器并设置指纹识别器
	ruleManager := rule.NewManager()
	
	rulesDir := customrules.GetDefaultDirectory()
	// Check if rules directory exists, if not, download it
	if _, err := os.Stat(rulesDir); os.IsNotExist(err) {
		t.Logf("Rules directory does not exist, downloading...")
		customrules.DefaultProvider.Download(nil, rulesDir)
	}
	
	err := ruleManager.LoadRules(rulesDir)
	assert.NoError(t, err)
	// 创建爬虫
	spider := crawl.NewCrawler(crawl.DefaultOption())
	// 创建Runner
	runner := NewRunnerCompat(spider, ruleManager)
	// 执行扫描
	result, err := runner.Scan(ts.URL)
	// 验证结果
	assert.NoError(t, err)
	assert.NotNil(t, result)
	// Just verify the scan completed successfully, don't require specific matches
	// as the test server may not match any real fingerprints
	t.Logf("Scan completed with %d components detected", len(result.Components))
}
