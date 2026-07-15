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

// NewFetcher 创建新的Fetcher实例。
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
		transport := retryablehttp.DefaultReusePooledTransport()
		// 使用标准 Dialer 让连接建立阶段受 request ctx 取消/超时控制，
		// 避免 fastdialer 默认拨号超时覆盖 Options.Timeout。
		transport.DialContext = (&net.Dialer{}).DialContext
		if c.options.Proxy != "" {
			proxyURL, proxyErr := url.Parse(c.options.Proxy)
			transport.Proxy = func(request *http.Request) (*url.URL, error) {
				return proxyURL, proxyErr
			}
		}
		opts := retryablehttp.Options{
			RetryWaitMin: 1 * time.Second,    // 单次重试前的最小等待时间。
			RetryWaitMax: 30 * time.Second,   // 单次重试前的最大等待时间。
			RetryMax:     c.options.RetryMax, // 最大重试次数，来自 fetch.Options/CLI 配置。
			// 重试前最多读取并丢弃 4KB 响应体，让连接有机会复用，同时避免 drain 大响应。
			RespReadLimit: 4096,
			// 请求超时由 RequestOnce/readICON 根据调用方 ctx 和 Options.Timeout 控制，
			// 避免 retryablehttp 的 client-level timeout 抢先截断外部传入的 deadline。
			Timeout: 0,
			// 这里使用可复用连接池，不能沿用 host spraying 场景的 idle 连接关闭策略。
			KillIdleConn: false,
			// client-level timeout 已关闭，禁用 retryablehttp 的自动 timeout 调整逻辑。
			NoAdjustTimeout: true,
			// 使用上面配置了连接池、proxy 和标准 Dialer 的 http client。
			HttpClient: &http.Client{Transport: transport},
		}
		c.httpClient = retryablehttp.NewClient(opts)
	})
}

// GetClient 获取HTTP客户端
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
				if banner.Certificate != "" {
					fmt.Println("Dump Cert For " + banner.Uri + "\r\n" + banner.Certificate)
				}
				fmt.Println("Dump Response For " + banner.Uri + "\r\n" + banner.Response)
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
			gologger.Print().Msgf("Dump Icon For %s -> %d", finalBanner.IconURI, finalBanner.IconHash)
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
