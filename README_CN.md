# AppFinger

<p align="center">
  <img src="docs/img.png" alt="AppFinger detection overview" width="720">
</p>

<p align="center">
  <img alt="Go" src="https://img.shields.io/badge/Go-1.23-00ADD8?logo=go&logoColor=white">
  <img alt="License" src="https://img.shields.io/badge/License-MIT-green.svg">
  <img alt="Rules" src="https://img.shields.io/badge/rules-finger--rules-blueviolet">
  <img alt="Mode" src="https://img.shields.io/badge/CLI%20%2B%20Library-ready-orange">
</p>

*[English](README.md) | [中文](README_CN.md)*

AppFinger 是一个快速的 HTTP 应用指纹识别工具，也可以作为 Go 库集成使用。它会采集目标的响应体、响应头、标题、证书、favicon hash、body hash 以及客户端跳转信息，并使用 YAML 指纹规则进行匹配。

指纹规则独立维护在 [hexbay/finger-rules](https://github.com/hexbay/finger-rules)。

## ✨ 功能特性

- 🌐 HTTP banner 与响应指纹识别
- 🎯 支持响应头、响应体、标题、状态码、证书、favicon hash、body hash 匹配
- 🔁 支持 HTTP 重定向、meta refresh 与轻量 JavaScript 跳转解析
- ⚡ 支持多目标并发扫描
- 🧰 支持代理、超时、stdin、文件输入与 JSON 输出
- 🧱 WordPress 插件和主题增强识别
- ✅ 支持规则严格校验
- 🧪 既可作为命令行工具使用，也可作为 Go 库调用

## 📦 安装

从源码构建：

```bash
git clone https://github.com/hexbay/appfinger.git
cd appfinger
go build -o appfinger .
```

通过 Go 安装：

```bash
go install github.com/hexbay/appfinger@latest
```

## 🚀 快速开始

扫描单个目标：

```bash
appfinger -u https://example.com
```

扫描多个目标：

```bash
appfinger -u https://example.com -u https://example.org
```

从文件读取目标：

```bash
appfinger -l urls.txt -t 30 -o result.json -output-format json
```

从标准输入读取目标：

```bash
cat urls.txt | appfinger -s
```

使用 HTTP 代理：

```bash
appfinger -u https://example.com -x http://127.0.0.1:7890
```

## ⚙️ 命令行参数

```text
APPFINGER:
  -u, -url string[]          要扫描的目标 URL（-u INPUT1 -u INPUT2）
  -l, -url-file string       包含目标 URL 的文件
  -s, -stdin                 从标准输入读取 URL
  -t, -threads int           并发线程数（默认 10）
  -timeout int               超时时间，单位秒（默认 10）
  -x, -proxy string          HTTP 代理，例如 http://127.0.0.1:7890
  -d, -finger-home string    指纹 YAML 规则目录
  -ur, -update-rule          从 finger-rules 仓库更新规则
  -di, -disable-icon         禁用 favicon 获取和 icon hash 匹配
  -dj, -disable-js           禁用 JavaScript 跳转解析
  -debug-req                 输出 HTTP 请求内容
  -debug-resp                输出 HTTP 响应内容
  -v, -version               显示版本
  -validate                  校验规则并退出

OUTPUT:
  -o, -output string         输出文件路径
  -output-format string      输出格式：txt 或 json（默认 txt）

HELP:
  -debug                     启用调试日志
```

## 🧩 指纹规则库

AppFinger 使用 [finger-rules](https://github.com/hexbay/finger-rules) 中的 YAML 指纹规则。
默认规则目录不存在时，AppFinger 会自动下载 `finger-rules` 完成初始化。

更新本地规则库：

```bash
appfinger -update-rule
```

指定自定义规则目录：

```bash
appfinger -u https://example.com -d /path/to/finger-rules
```

扫描前校验规则：

```bash
appfinger -validate -d /path/to/finger-rules
```

## 🛠️ 作为 Go 库使用

```go
package main

import (
	"context"
	"fmt"
	"time"

	"github.com/hexbay/appfinger/pkg/fetch"
	"github.com/hexbay/appfinger/pkg/rule"
	"github.com/hexbay/appfinger/pkg/scanner"
)

func main() {
	fetchOptions := fetch.DefaultOption()
	fetchOptions.Timeout = 10 * time.Second
	fetcher := fetch.NewFetcher(fetchOptions)

	manager, err := rule.LoadDefaultRules(context.Background())
	if err != nil {
		panic(err)
	}

	r, err := scanner.New(scanner.Config{Fetcher: fetcher, Rules: manager.GetFinger()})
	if err != nil {
		panic(err)
	}
	result, err := r.Scan(context.Background(), "https://example.com")
	if err != nil {
		panic(err)
	}

	fmt.Printf("%#v\n", result.Components)
}
```

公共扫描 API 是 `scanner.New` 和 `Scanner.Scan`。HTTP 行为由
`fetch.Options` 控制；目标枚举和输出由 CLI 内部的 `enumerate`、`report` 包负责。

## 🔎 工作原理

AppFinger 会先请求目标 HTTP 服务，并将响应中的关键信息整理为 banner。随后规则引擎会对响应体、响应头、标题、证书、favicon hash、状态码等字段执行 YAML matcher 匹配。

![Deep Detection Comparison](docs/img.png)

## 🧪 开发

运行测试：

```bash
go test ./...
```

本地构建：

```bash
go build ./...
```

## 🤝 贡献

欢迎提交 issue 或 pull request。如果新增或调整指纹识别行为，建议同时补充聚焦的测试用例。

## 📄 许可证

AppFinger 使用 MIT License。详情见 [LICENSE](LICENSE)。
