package wordpress

import (
	"regexp"
)

// 单独匹配wordpress 插件
var pluginReg = regexp.MustCompile(`/wp-content/(plugins|themes)/([\w-]+)/(?:.*\?ver=([\d.]+))?`)

// MatchPlugins 匹配WordPress插件和主题。
func MatchPlugins(body string) map[string]map[string]string {
	matchedPaths := pluginReg.FindAllStringSubmatch(body, -1)
	pluginInfo := make(map[string]map[string]string)
	for _, matches := range matchedPaths {
		if len(matches) > 2 {
			name := matches[2]
			pluginInfo[name] = map[string]string{"framework": "wordpress"}
			if len(matches) > 2 {
				pluginVersion := matches[3]
				pluginInfo[name]["version"] = pluginVersion
				pluginInfo[name]["type"] = matches[1]
			}
		}
	}
	return pluginInfo
}
