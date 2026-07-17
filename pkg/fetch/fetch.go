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
	"time"
)

// Fetcher 定义HTTP探测和Banner采集的核心结构。
type Fetcher struct {
	options    *Options
	httpClient *retryablehttp.Client
}

// NewFetcher creates a Fetcher. Prefer this constructor for the public fetch API.

func NewFetcher(options *Options) (*Fetcher, error) {
	normalized, err := normalizeOptions(options)
	if err != nil {
		return nil, err
	}
	baseClient, err := buildHTTPClient(normalized)
	if err != nil {
		return nil, err
	}
	client := retryablehttp.NewClient(retryablehttp.Options{
		RetryWaitMin: 1 * time.Second,    // 单次重试前的最小等待时间。
		RetryWaitMax: 30 * time.Second,   // 单次重试前的最大等待时间。
		RetryMax:     normalized.Retries, // 失败后的额外重试次数。
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
		HttpClient: baseClient,
	})
	return &Fetcher{options: normalized, httpClient: client}, nil
}

func normalizeOptions(options *Options) (*Options, error) {
	result := DefaultOption()
	if options != nil {
		*result = *options
	}
	if result.Timeout < 0 {
		return nil, fmt.Errorf("timeout must not be negative")
	}
	if result.Retries < 0 {
		return nil, fmt.Errorf("retries must not be negative")
	}
	if result.Proxy != "" {
		u, err := url.Parse(result.Proxy)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return nil, fmt.Errorf("invalid proxy URL %q", result.Proxy)
		}
	}
	return result, nil
}

func buildHTTPClient(options *Options) (*http.Client, error) {
	if options.HTTPClient != nil {
		return disableAutoRedirect(options.HTTPClient), nil
	}
	if options.Transport != nil {
		return disableAutoRedirect(&http.Client{Transport: options.Transport}), nil
	}
	transport := retryablehttp.DefaultReusePooledTransport()
	transport.DialContext = (&net.Dialer{}).DialContext
	transport.DialTLSContext = nil
	transport.MaxResponseHeaderBytes = DefaultMaxResponseHeaderBytes
	if options.Timeout > 0 {
		transport.TLSHandshakeTimeout = options.Timeout
	}
	if options.Proxy != "" {
		proxyURL, err := url.Parse(options.Proxy)
		if err != nil {
			return nil, err
		}
		transport.Proxy = http.ProxyURL(proxyURL)
	}
	return disableAutoRedirect(&http.Client{Transport: transport}), nil
}

func disableAutoRedirect(client *http.Client) *http.Client {
	result := *client
	if result.CheckRedirect == nil {
		result.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}
	return &result
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
			banner, nextURI, err = requestOnce(ctx, c.httpClient, nextURI, c.options)
			if err != nil {
				gologger.Debug().Msgf("Req Error:%v", err)
				break RedirectLoop
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
		if err != nil {
			return nil, fmt.Errorf("get %s: %w: %w", uri, ErrFetch, err)
		}
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
