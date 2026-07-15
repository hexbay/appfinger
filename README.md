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

AppFinger is a fast HTTP application fingerprint scanner and Go library. It fetches web banners, headers, titles, certificates, favicon hashes, and client-side redirects, then matches them against YAML fingerprint rules.

Rules are maintained separately in [hexbay/finger-rules](https://github.com/hexbay/finger-rules).

## ✨ Features

- 🌐 HTTP banner and response fingerprinting
- 🎯 Header, body, title, status code, certificate, favicon hash, and body hash matching
- 🔁 HTTP redirect, meta refresh, and lightweight JavaScript redirect handling
- ⚡ Concurrent target scanning
- 🧰 Optional proxy, timeout, stdin, file input, and JSON output
- 🧱 WordPress plugin and theme enhancement detection
- ✅ Strict rule validation mode
- 🧪 Usable both as a CLI and as a Go library

## 📦 Installation

Build from source:

```bash
git clone https://github.com/hexbay/appfinger.git
cd appfinger
go build -o appfinger .
```

Or install with Go:

```bash
go install github.com/hexbay/appfinger@latest
```

## 🚀 Quick Start

Scan one target:

```bash
appfinger -u https://example.com
```

Scan multiple targets:

```bash
appfinger -u https://example.com -u https://example.org
```

Scan from a file:

```bash
appfinger -l urls.txt -t 30 -o result.json -output-format json
```

Scan from stdin:

```bash
cat urls.txt | appfinger -s
```

Use an HTTP proxy:

```bash
appfinger -u https://example.com -x http://127.0.0.1:7890
```

## ⚙️ CLI Options

```text
APPFINGER:
  -u, -url string[]          Target URL to scan (-u INPUT1 -u INPUT2)
  -l, -url-file string       File containing URLs to scan
  -s, -stdin                 Read URLs from stdin
  -t, -threads int           Number of concurrent threads (default 10)
  -timeout int               Timeout in seconds (default 10)
  -x, -proxy string          HTTP proxy, e.g. http://127.0.0.1:7890
  -d, -finger-home string    Fingerprint YAML directory
  -ur, -update-rule          Update rules from the finger-rules repository
  -di, -disable-icon         Disable favicon fetching and icon hash matching
  -dj, -disable-js           Disable JavaScript redirect parsing
  -debug-req                 Dump HTTP requests
  -debug-resp                Dump HTTP responses
  -v, -version               Show version
  -validate                  Validate rules and exit

OUTPUT:
  -o, -output string         File to write output to
  -output-format string      Output format: txt or json (default txt)

HELP:
  -debug                     Enable debug logs
```

## 🧩 Rule Repository

AppFinger uses YAML rules from [finger-rules](https://github.com/hexbay/finger-rules).
When the default rule directory does not exist, AppFinger initializes it automatically by downloading `finger-rules`.

Update the local rule repository:

```bash
appfinger -update-rule
```

Use a custom rule directory:

```bash
appfinger -u https://example.com -d /path/to/finger-rules
```

Validate rules before scanning:

```bash
appfinger -validate -d /path/to/finger-rules
```

## 🛠️ Library Usage

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

The public scanning API is `scanner.New` and `Scanner.Scan`. HTTP behavior is
configured only through `fetch.Options`: `Timeout` is the timeout for one HTTP
request chain and `Retries` is the number of additional attempts after a
failure. `Retries` defaults to `0`. The same request context is used for the
retry chain, so its maximum duration is bounded by the configured timeout
(unless the caller's context has an earlier deadline). Target enumeration and
output are separate concerns handled by the CLI's internal `enumerate` and `report` packages.

## 🔎 How It Works

AppFinger fetches target HTTP responses and normalizes useful matching data into banners. The rule engine then evaluates YAML matchers against response parts such as body, headers, title, certificate, favicon hash, and status code.

![Deep Detection Comparison](docs/img.png)

## 🧪 Development

Run tests:

```bash
go test ./...
```

Build locally:

```bash
go build ./...
```

## 🤝 Contributing

Issues and pull requests are welcome. If you add or modify fingerprint behavior, please include focused tests where possible.

## 📄 License

AppFinger is licensed under the MIT License. See [LICENSE](LICENSE) for details.
