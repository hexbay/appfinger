package fetch

import "time"

const (
	DefaultMaxBodySize int64 = 5 * 1024 * 1024
	DefaultMaxIconSize int64 = 512 * 1024
)

type Options struct {
	DisableIcon       bool
	Proxy             string
	DebugReq          bool
	DebugResp         bool
	DisableJavaScript bool
	MaxBodySize       int64
	MaxIconSize       int64
	Timeout           time.Duration
	RetryMax          int // 重试次数
}

func DefaultOption() *Options {
	return &Options{
		DisableIcon:       false,
		Proxy:             "",
		DebugReq:          false,
		DebugResp:         false,
		DisableJavaScript: false,
		MaxBodySize:       DefaultMaxBodySize,
		MaxIconSize:       DefaultMaxIconSize,
		Timeout:           6 * time.Second,
		RetryMax:          1,
	}

}
