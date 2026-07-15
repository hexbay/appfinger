package fetch

import (
	"context"
	"errors"
	"fmt"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/retryablehttp-go"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// Fetcher 定义HTTP探测和Banner采集的核心结构。
type Fetcher struct {
	options      *Options
	httpClient   *retryablehttp.Client
	clientInitMu sync.Once
}

// NewFetcher creates a Fetcher. Prefer this constructor for the public fetch API.
func NewFetcher(options *Options) *Fetcher {
	if options == nil {
		options = DefaultOption()
	}
	c := &Fetcher{options: options}
	c.initClient()
	return c
}

// initClient 初始化HTTP客户端
func (c *Fetcher) initClient() {
	c.clientInitMu.Do(func() {
		opts := retryablehttp.Options{
			RetryWaitMin: 1 * time.Second,           // 单次重试前的最小等待时间。
			RetryWaitMax: 30 * time.Second,          // 单次重试前的最大等待时间。
			RetryMax:     max(0, c.options.Retries), // 失败后的额外重试次数。
			// 重试前最多读取并丢弃 4KB 响应体，让连接有机会复用，同时避免 drain 大响应。
			RespReadLimit: 4096,
			// 请求超时由 RequestOnce/readICON 根据调用方 ctx 和 Options.Timeout 控制，
			// 避免 retryablehttp 的 client-level timeout 抢先截断外部传入的 deadline。
			Timeout: 0,
			// 这里使用可复用连接池，不能沿用 host spraying 场景的 idle 连接关闭策略。
			KillIdleConn: false,
			// client-level timeout 已关闭，禁用 retryablehttp 的自动 timeout 调整逻辑。
			NoAdjustTimeout: true,
			// 使用 appfinger 默认 client，或调用方注入的自定义 client。
			HttpClient: c.buildBaseHTTPClient(),
		}
		c.httpClient = retryablehttp.NewClient(opts)
	})
}

func (c *Fetcher) buildBaseHTTPClient() *http.Client {
	if c.options.HTTPClient != nil {
		return c.options.HTTPClient
	}
	if c.options.Transport != nil {
		return &http.Client{Transport: c.options.Transport}
	}

	transport := retryablehttp.DefaultReusePooledTransport()
	// 使用标准 Dialer 让连接建立阶段受 request ctx 取消/超时控制，
	// 避免 fastdialer 默认拨号超时覆盖 Options.Timeout。
	transport.DialContext = (&net.Dialer{}).DialContext
	// 清空 retryablehttp 默认注入的 fastdialer TLS 拨号路径，让 HTTPS 也走标准 DialContext。
	transport.DialTLSContext = nil
	if c.options.Timeout > 0 {
		transport.TLSHandshakeTimeout = c.options.Timeout
	}
	if c.options.Proxy != "" {
		proxyURL, proxyErr := url.Parse(c.options.Proxy)
		transport.Proxy = func(request *http.Request) (*url.URL, error) {
			return proxyURL, proxyErr
		}
	}
	return &http.Client{Transport: transport}
}

// GetClient exposes the internal retryable HTTP client for compatibility.
// New code should use GetBanner or GetBanners instead.
//
// Deprecated: direct client access couples callers to retryablehttp.
func (c *Fetcher) GetClient() *retryablehttp.Client {
	c.initClient()
	return c.httpClient
}

// GetBanners 实现BannerProvider接口
func (c *Fetcher) GetBanners(ctx context.Context, uri string) ([]*Banner, error) {
	var banners []*Banner
	var nextURI = uri
	var banner *Banner
	var err error
	// 处理重定向，最多跟踪3次
RedirectLoop:
	for ret := 0; ret < 3; ret++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
			banner, nextURI, err = RequestOnce(ctx, c.httpClient, nextURI, c.options)
			if err != nil {
				gologger.Debug().Msgf("Req Error:%v", err)
				break RedirectLoop
			}
			if c.options.DebugResp {
				gologger.Debug().Msgf("response captured for %s", banner.Uri)
			}
			// 如果nextURI为空，则不再继续请求
			if nextURI == "" {
				banners = append(banners, banner)
				break RedirectLoop
			}

			banners = append(banners, banner)
			if nextURI == "" {
				break
			}
		}
	}
	if len(banners) == 0 {
		return nil, errors.New(fmt.Sprintf("Get %s Error!", uri))
	}
	// 获取最后一个Banner（最终页面）
	finalBanner := banners[len(banners)-1]
	// 获取网站图标
	if !c.options.DisableIcon {
		_, err = readICON(ctx, c.httpClient, finalBanner, c.options)
		if err != nil {
			gologger.Debug().Msg(err.Error())
		}
		if c.options.DebugResp && finalBanner.IconHash > 0 {
			gologger.Debug().Msgf("icon captured for %s", finalBanner.IconURI)
		}
	}
	return banners, nil
}

func (c *Fetcher) GetBanner(ctx context.Context, uri string) (*Banner, error) {
	banners, err := c.GetBanners(ctx, uri)
	if err != nil {
		return nil, err
	}
	return banners[0], nil
}
