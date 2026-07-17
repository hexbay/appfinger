package fetch

import (
	"net/http"
	"time"
)

const (
	DefaultMaxBodySize                   int64 = 5 * 1024 * 1024
	DefaultMaxIconSize                   int64 = 512 * 1024
	DefaultMaxJavaScriptRedirectBodySize int64 = 64 * 1024
	DefaultMaxResponseHeaderBytes        int64 = 10 * 1024 * 1024
)

type Options struct {
	DisableIcon                   bool
	Proxy                         string
	DebugReq                      bool
	DebugResp                     bool
	DisableJavaScript             bool
	MaxBodySize                   int64
	MaxIconSize                   int64
	MaxJavaScriptRedirectBodySize int64
	Timeout                       time.Duration
	Retries                       int // 失败后的额外重试次数，默认 0
	// HTTPClient allows SDK users to provide a fully configured client.
	// When set, appfinger uses it as-is and does not mutate transport settings.
	HTTPClient *http.Client
	// Transport allows SDK users to provide custom transport-level behavior.
	// When set, appfinger wraps it in an http.Client and does not mutate it.
	Transport *http.Transport
}

func DefaultOption() *Options {
	return &Options{
		DisableIcon:                   false,
		Proxy:                         "",
		DebugReq:                      false,
		DebugResp:                     false,
		DisableJavaScript:             false,
		MaxBodySize:                   DefaultMaxBodySize,
		MaxIconSize:                   DefaultMaxIconSize,
		MaxJavaScriptRedirectBodySize: DefaultMaxJavaScriptRedirectBodySize,
		Timeout:                       6 * time.Second,
		Retries:                       0,
	}

}
