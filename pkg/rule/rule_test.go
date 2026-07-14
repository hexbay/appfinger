package rule

import (
	"fmt"
	"github.com/hexbay/appfinger/pkg/external/customrules"
	"github.com/hexbay/appfinger/pkg/fetch"
	"github.com/hexbay/appfinger/pkg/matchers"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"
)

// CreateMatchPartGetter 创建一个从banner中提取匹配部分的函数
func CreateMatchPartGetter(banner *fetch.Banner) MatchPartGetter {
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
	// CaseSensitive 为 true 的时候大小写敏感
	return func(part string, caseSensitive bool) string {
		if !caseSensitive {
			if strings.Contains(part, "headers.") {
				part = part[8:]
			}
			if value, ok := lowerCache[part]; ok {
				return value
			}
		}
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

func TestRuleMatchHonorsCaseSensitive(t *testing.T) {
	r := &Rule{
		Name: "case-sensitive-rule",
		Matchers: []*matchers.Matcher{
			{
				Type:          matchers.MatcherTypeHolder{MatcherType: matchers.WordsMatcher},
				Words:         []string{"AppFinger"},
				CaseSensitive: true,
			},
		},
	}
	for _, matcher := range r.Matchers {
		if err := matcher.CompileMatchers(); err != nil {
			t.Fatal(err)
		}
	}

	matched, _ := r.Match(func(part string, caseSensitive bool) string {
		if !caseSensitive {
			return strings.ToLower("appfinger")
		}
		return "appfinger"
	})
	if matched {
		t.Fatal("case-sensitive matcher should not match different casing")
	}
}

func TestLoadRule(t *testing.T) {
	rulesDir := customrules.GetDefaultDirectory()

	// Check if rules directory exists, if not, download it
	if _, err := os.Stat(rulesDir); os.IsNotExist(err) {
		t.Logf("Rules directory does not exist, downloading...")
		customrules.DefaultProvider.Download(nil, rulesDir)
		// Wait a bit for download to complete
		time.Sleep(2 * time.Second)
	}

	finger, err := ScanRuleDirectory(rulesDir)
	if err != nil {
		t.Error(err)
		return
	}
	for name, rules := range finger.Rules {
		t.Log("load", name, "rules:", len(rules))
	}
}

func TestRuleMatchFtp(t *testing.T) {
	rulesDir := customrules.GetDefaultDirectory()

	// Check if rules directory exists, if not, download it
	if _, err := os.Stat(rulesDir); os.IsNotExist(err) {
		t.Logf("Rules directory does not exist, downloading...")
		customrules.DefaultProvider.Download(nil, rulesDir)
		time.Sleep(2 * time.Second)
	}

	finger, err := ScanRuleDirectory(rulesDir)
	if err != nil {
		t.Error(err)
		return
	}
	results := finger.Match("http", func(part string, caseSensitive bool) string {
		return "Adobe Media Server"
	})
	t.Log(results)

	results = finger.Match("ftp", func(part string, caseSensitive bool) string {
		return "220 Microsoft FTP Service\n214-The following commands are recognized (* ==>'s unimplemented).\nABOR\nACCT"
	})
	t.Log(results)
}

func TestRuleMatchCpe(t *testing.T) {
	gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)
	rulesDir := customrules.GetDefaultDirectory()

	// Check if rules directory exists, if not, download it
	if _, err := os.Stat(rulesDir); os.IsNotExist(err) {
		t.Logf("Rules directory does not exist, downloading...")
		customrules.DefaultProvider.Download(nil, rulesDir)
		time.Sleep(2 * time.Second)
	}

	finger, err := ScanRuleDirectory(rulesDir)
	if err != nil {
		t.Error(err)
		return
	}
	results := finger.Match("ssh", func(part string, caseSensitive bool) string { return "SSH-2.0-OpenSSH_7.2p2 Ubuntu-4kord2.8" })
	t.Log(results)
}

func BenchmarkMatch(b *testing.B) {
	// 压力测试
	runtime.GOMAXPROCS(1)
	rulesDir := customrules.GetDefaultDirectory()

	// Check if rules directory exists, if not, download it
	if _, err := os.Stat(rulesDir); os.IsNotExist(err) {
		b.Logf("Rules directory does not exist, downloading...")
		customrules.DefaultProvider.Download(nil, rulesDir)
		time.Sleep(2 * time.Second)
	}

	finger, err := ScanRuleDirectory(rulesDir)
	if err != nil {
		panic(err)
	}
	cpuFile, err := os.Create("cpu_profile.prof")
	if err != nil {
		b.Fatal(err)
	}
	defer cpuFile.Close()
	_ = b.Run("Match Http", func(b *testing.B) {
		// 准备测试数据
		b.ResetTimer()
		banner := &fetch.Banner{
			Title:  "测试标题",
			Uri:    "http://127.0.0.1:8080",
			Header: "HTTP/1.1 500 Internal Server Error\\r\\nTransfer-Encoding: chunked\\r\\nConnection: keep-alive\\r\\nContent-Type: text/html; charset=UTF-8\\r\\nDate: Sun, 24 Aug 2025 11:32:33 GMT\\r\\nServer: nginx\\r\\n\\r\\n",
			Headers: map[string]string{
				"host":            "127.0.0.1:8080",
				"server":          "nginx",
				"user-agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.149 Safari/537.36",
				"accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
				"accept-language": "zh-CN,zh;q=0.9",
				"accept-encoding": "gzip, deflate",
				"connection":      "close",
			},
			Body:     "<!doctype html>\\r\\n<html lang=\\\"zh-Hans\\\">\\r\\n<head>\\r\\n    <meta charset=\\\"utf-8\\\" />\\r\\n    <meta name=\\\"robots\\\" content=\\\"noindex,nofollow,noarchive\\\" />\\r\\n    <meta name=\\\"generator\\\" content=\\\"\\\"/>\\r\\n    <meta http-equiv=\\\"X-UA-Compatible\\\" content=\\\"ie=edge\\\"/>\\r\\n    <meta name=\\\"renderer\\\" content=\\\"webkit\\\" />\\r\\n    <meta name=\\\"viewport\\\" content=\\\"width=device-width,viewport-fit=cover\\\" />\\r\\n    <title>我的网站-错误</title>\\r\\n    <link rel=\\\"stylesheet\\\" href=\\\"http://www.zjpxzz.cn/zb_system/css/admin.css?173050\\\" type=\\\"text/css\\\" media=\\\"screen\\\"/>\\r\\n    <script src=\\\"http://www.zjpxzz.cn/zb_system/script/common.js?173050\\\"></script>\\r\\n    \\r\\n</head>\\r\\n<body class=\\\"error short\\\">\\r\\n<div class=\\\"bg\\\">\\r\\n    <div id=\\\"wrapper\\\">\\r\\n        <div class=\\\"logo\\\"><img src=\\\"http://www.zjpxzz.cn/zb_system/image/admin/none.gif\\\" title=\\\"Z-BlogPHP\\\"\\r\\n                               alt=\\\"Z-BlogPHP\\\"/></div>\\r\\n        <div class=\\\"login loginw\\\">\\r\\n            <form id=\\\"frmLogin\\\" method=\\\"post\\\" action=\\\"#\\\">\\r\\n                                    <div class=\\\"divHeader lessinfo\\\" style=\\\"margin-bottom:10px;\\\">\\r\\n                        <b>MySQL数据库无法连接</b></div>\\r\\n                    <div class=\\\"content lessinfo\\\">\\r\\n                        <div>\\r\\n                            <p style=\\\"font-weight: normal;\\\">可能的错误原因</p>\\r\\n                            \\r\\n                您在zb_users/c_option.php内配置、或刚才填写的的 MySQL 连接信息是否正确？<br/>\\r\\n                您所连接的 MySQL 数据库是否已经成功启动？<br/>\\r\\n                <br/>\\r\\n            \\r\\n请复制上方错误信息到搜索引擎以获取关于该错误的说明，或点击<a href=\\\"https://cn.bing.com/search?q=MySQL%E6%95%B0%E6%8D%AE%E5%BA%93%E6%97%A0%E6%B3%95%E8%BF%9E%E6%8E%A5\\\" rel=\\\"nofollow\\\" target=\\\"_blank\\\">「使用必应搜索」。</a><br/><br/>\\r\\n\\r\\n如果您是访客，这说明网站程序可能出现了一些错误。请您稍后再试，或联系站长。<br/><br/>\\r\\n\\r\\n如果您是站长，可以<a href=\\\"https://docs.zblogcn.com/php/#/books/start-faq\\\" rel=\\\"nofollow\\\" target=\\\"_blank\\\">「点击这里」</a>查看 Z-Blog 官方对于【部分常见错误 】的说明,，以及<a href=\\\"https://docs.zblogcn.com/php/#/books/start-faq\\\" rel=\\\"nofollow\\\" target=\\\"_blank\\\">「通用排查指南」</a>。<br/>\\r\\n\\r\\n如果仍然无法解决，也可以到 <a href=\\\"https://bbs.zblogcn.com/\\\" rel=\\\"nofollow\\\" target=\\\"_blank\\\">Z-Blog 官方论坛</a>，附上当前错误信息与描述寻求帮助。\\r\\n注：请将\\\"当前错误信息\\\"复制进标题或正文中。<br/>\\r\\n                                </div>\\r\\n                    </div>\\r\\n                        \\r\\n                <div class=\\\"goback\\\">\\r\\n                    <a href=\\\"javascript:history.back(-1);\\\">返回</a>&nbsp;&nbsp;&nbsp;&nbsp;\\r\\n                    <a href=\\\"javascript:location.reload();\\\">刷新</a>&nbsp;&nbsp;&nbsp;&nbsp;\\r\\n                    <a href=\\\"http://www.zjpxzz.cn/zb_system/cmd.php?act=login\\\">登录</a>\\r\\n                </div>\\r\\n            </form>\\r\\n        </div>\\r\\n    </div>\\r\\n</div>\\r\\n</body>\\r\\n</html><!--16.52 ms , 0 query , 1364kb memory , 2 errors-->",
			IconHash: 0x100100,
			BodyHash: 0x100100,
			IconType: "svg",
			IconURI:  "http://127.0.0.1:8080/favicon.ico",
			IconBytes: []byte{
				0x3C, 0x3F, 0x78, 0x6D, 0x6C, 0x20, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6F, 0x6E, 0x3D, 0x22, 0x31,
				0x2E, 0x30, 0x22, 0x20, 0x65, 0x6E, 0x63, 0x6F, 0x64, 0x69, 0x6E, 0x67, 0x3D, 0x22, 0x55, 0x54,
				0x46, 0x2D, 0x38, 0x22, 0x20, 0x73, 0x74, 0x61, 0x6E, 0x64, 0x61, 0x6C, 0x6F, 0x6E, 0x65, 0x3D,
				0x22, 0x79, 0x65, 0x73, 0x22, 0x3E, 0x3C, 0x21, 0x2D, 0x2D, 0x20, 0x43, 0x72, 0x65, 0x61, 0x74},
			Cert:        nil,
			Certificate: "SSL Certificate\\nVersion: TLS 1.3\\nCipherSuit:TLS_AES_256_GCM_SHA384\\nCertificate:\\n\\tSignature Algorithm: SHA256-RSA\\n\\t\\tIssuer: C=US,CN=R10,O=Let's Encrypt\\n\\tValidity:\\n\\t\\tNot Before: 2025-02-24 16:11:44\\n\\t\\tNot After : 2025-05-25 16:11:43\\n\\tSubject: CN=app.xxx.site\\n",
		}
		matchPartGetter := CreateMatchPartGetter(banner)
		// 重置计时器
		//b.ResetTimer()
		// 手动计时
		start := time.Now()
		// 执行测试
		for i := 0; i < b.N; i++ {
			// 存储结果以防止编译器优化
			result := finger.Match("http", matchPartGetter)
			// 使用结果防止优化
			if result != nil && i == -1 { // 永远不会执行的条件
				b.Log(result)
			}
		}
		// 计算总耗时
		totalTime := time.Since(start)
		b.ReportMetric(totalTime.Seconds(), "total_time_s")
	})
}
