// Package scanner contains AppFinger's single-target scanning engine.
// It is safe to share one Scanner between callers; concurrency is owned by
// the caller (for example xmap), not by this package.
package scanner

import (
	"context"
	"fmt"
	"net/url"
	"path"
	"strings"

	"github.com/hexbay/appfinger/pkg/detectors/wordpress"
	"github.com/hexbay/appfinger/pkg/fetch"
	"github.com/hexbay/appfinger/pkg/rule"
)

type Result struct {
	Target     string
	Banner     *fetch.Banner
	Components map[string]map[string]string
}

type Config struct {
	Fetcher *fetch.Fetcher
	Rules   *rule.RuleSet
}

type Scanner struct {
	fetcher *fetch.Fetcher
	rules   *rule.RuleSet
}

func New(config Config) (*Scanner, error) {
	if config.Fetcher == nil {
		return nil, fmt.Errorf("scanner fetcher is required")
	}
	if config.Rules == nil {
		return nil, fmt.Errorf("scanner rules are required")
	}
	return &Scanner{fetcher: config.Fetcher, rules: config.Rules}, nil
}

func (s *Scanner) Scan(ctx context.Context, target string) (*Result, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	banners, err := s.collect(ctx, target)
	if err != nil {
		return nil, err
	}
	finger := s.rules
	components, plugins := matchBanners(finger, banners)
	if _, ok := components["honeypot"]; ok {
		components = map[string]map[string]string{"honeypot": {}}
	}
	last := banners[len(banners)-1]
	if _, ok := components["Wordpress"]; ok {
		components = merge(wordpress.MatchPlugins(last.Body), components)
	}
	components, last, err = s.executePlugins(ctx, finger, components, last, plugins)
	if err != nil {
		return nil, err
	}
	return &Result{Target: target, Banner: last, Components: components}, nil
}

func (s *Scanner) collect(ctx context.Context, target string) ([]*fetch.Banner, error) {
	return s.fetcher.GetBanners(ctx, target)
}

func (s *Scanner) executePlugins(ctx context.Context, finger *rule.RuleSet, components map[string]map[string]string, last *fetch.Banner, plugins []pluginRequest) (map[string]map[string]string, *fetch.Banner, error) {
	seen := make(map[string]struct{})
	for _, p := range plugins {
		select {
		case <-ctx.Done():
			return components, last, ctx.Err()
		default:
		}
		uri := joinURL(p.banner.Uri, p.plugin.Path)
		if _, ok := seen[uri]; ok {
			continue
		}
		seen[uri] = struct{}{}
		pluginBanners, err := s.fetcher.GetBanners(ctx, uri)
		if err != nil || len(pluginBanners) == 0 {
			continue
		}
		matches, _ := matchBanners(finger, pluginBanners)
		components = merge(components, matches)
		last = pluginBanners[len(pluginBanners)-1]
	}
	return components, last, nil
}

type pluginRequest struct {
	plugin *rule.Plugin
	banner *fetch.Banner
}

func matchBanners(finger *rule.RuleSet, banners []*fetch.Banner) (map[string]map[string]string, []pluginRequest) {
	result := make(map[string]map[string]string)
	var plugins []pluginRequest
	for _, banner := range banners {
		for _, matched := range finger.Match("http", matchPart(banner)) {
			if matched.IsPlugin() {
				for _, p := range matched.Rule.Plugins {
					plugins = append(plugins, pluginRequest{p, banner})
				}
				continue
			}
			result[matched.Rule.Name] = matched.Extracted
		}
	}
	return result, plugins
}

func matchPart(b *fetch.Banner) rule.MatchPartGetter {
	lower := map[string]string{
		"body": strings.ToLower(b.Body), "header": strings.ToLower(b.Header),
		"title": strings.ToLower(b.Title), "response": strings.ToLower(b.Response),
		"cert": strings.ToLower(b.Certificate), "server": strings.ToLower(b.Headers["server"]),
	}
	for k, v := range b.Headers {
		lower[strings.ToLower(k)] = strings.ToLower(v)
	}
	return func(part string, sensitive bool) string {
		key := strings.TrimPrefix(strings.ToLower(part), "headers.")
		if !sensitive {
			if v, ok := lower[key]; ok {
				return v
			}
		}
		if strings.HasPrefix(part, "headers.") {
			return b.Headers[strings.ToLower(strings.TrimPrefix(part, "headers."))]
		}
		switch part {
		case "url":
			return b.Uri
		case "body":
			return b.Body
		case "header":
			return b.Header
		case "title":
			return b.Title
		case "response":
			return b.Response
		case "cert":
			return b.Certificate
		case "server":
			return b.Headers["server"]
		case "icon_hash":
			return fmt.Sprint(b.IconHash)
		case "body_hash":
			return fmt.Sprint(b.BodyHash)
		}
		return ""
	}
}

func merge(a, b map[string]map[string]string) map[string]map[string]string {
	for k, v := range b {
		a[k] = v
	}
	return a
}

func joinURL(base, suffix string) string {
	u, err := url.Parse(base)
	if err != nil {
		return base
	}
	u.Path = path.Join(u.Path, suffix)
	return u.String()
}
