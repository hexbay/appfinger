package runner

import (
	"fmt"
	"github.com/hexbay/appfinger/pkg/fetch"
	"strings"
)

// BannerAdapter 将fetch.Banner适配为matchers.BannerInfo
type BannerAdapter struct {
	banner *fetch.Banner
}

// GetMatchPart 实现BannerInfo接口的GetMatchPart方法
func (a *BannerAdapter) GetMatchPart(part string) string {
	if part == "" {
		part = "body"
	}
	if strings.HasPrefix(part, "headers.") {
		return a.banner.Headers[strings.ToLower(strings.TrimPrefix(part, "headers."))]
	}
	switch part {
	case "url":
		return a.banner.Uri
	case "body":
		return a.banner.Body
	case "header":
		return a.banner.Header
	case "cert":
		return a.banner.Certificate
	case "title":
		return a.banner.Title
	case "response":
		return a.banner.Response
	case "icon_hash":
		return fmt.Sprintf("%v", a.banner.IconHash)
	case "body_hash":
		return fmt.Sprintf("%v", a.banner.BodyHash)
	case "server":
		return a.banner.Headers["Server"]
	}
	return ""
}

// GetStatusCode 实现BannerInfo接口的GetStatusCode方法
func (a *BannerAdapter) GetStatusCode() int {
	return a.banner.StatusCode
}

// GetURI 实现BannerInfo接口的GetURI方法
func (a *BannerAdapter) GetURI() string {
	return a.banner.Uri
}
