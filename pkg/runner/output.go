package runner

import (
	"fmt"
	"github.com/hexbay/appfinger/pkg/fetch"
	"github.com/logrusorgru/aurora/v4"
	"strings"
	"unicode"
)

func formatConsole(target string, banner *fetch.Banner, components map[string]map[string]string) string {
	var s string
	s += aurora.Cyan(target).String()
	if banner.Title != "" {
		// 过滤换行
		cleanTitle := strings.Map(func(r rune) rune {
			if unicode.IsControl(r) {
				return -1 // 删除字符
			}
			return r
		}, banner.Title)
		s += fmt.Sprintf(" [%s]", aurora.Blue(cleanTitle).String())
	}
	for name, component := range components {
		v := name
		for k, kv := range component {
			v += fmt.Sprintf(" %s=%s", k, kv)
		}
		s += fmt.Sprintf(" [%s]", aurora.Green(v))
	}

	if server, ok := banner.Headers["server"]; ok {
		s += fmt.Sprintf(" [%s]", aurora.Yellow(server).String())
	}
	if banner.Cert != nil {
		s += fmt.Sprintf(" [%s]", aurora.Red(banner.Cert.ServerName))
	}
	return s
}
