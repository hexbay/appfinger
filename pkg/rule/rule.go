package rule

import (
	"github.com/hexbay/appfinger/pkg/matchers"
	"github.com/projectdiscovery/gologger"
	"strconv"
)

// MatchResult 表示匹配结果
type MatchResult struct {
	Rule      *Rule             // 匹配到的规则
	Extracted map[string]string // 提取的字段值
}

func (m MatchResult) IsPlugin() bool {
	return len(m.Rule.Plugins) > 0
}

type Plugin struct {
	Path string `yaml:"path" json:"path,omitempty"`
}

type Rule struct {
	Name              string `json:"name,omitempty"`
	Service           string `yaml:"service" json:"service,omitempty"`
	MatchersCondition string `yaml:"matchers-condition" json:"matchers_condition,omitempty"`
	// 组件太多  采用层级匹配 优化匹配速度
	Require  []string               `json:"require,omitempty"`
	Matchers []*matchers.Matcher    `json:"matchers,omitempty"`
	Plugins  []*Plugin              `yaml:"plugins"`
	Cpe      map[string]interface{} `yaml:"cpe" json:"cpe,omitempty"`
}

// Finger 根据协议分组
type Finger struct {
	Rules map[string][]*Rule `yaml:"rules"`
}

func (f Finger) AddRules(rules []*Rule) {
	for _, rule := range rules {
		if rule.Service == "" {
			rule.Service = "http"
		}
		f.Rules[rule.Service] = append(f.Rules[rule.Service], rule)
	}
}

// Match 执行指纹匹配并返回包含规则的匹配结果
func (f Finger) Match(service string, getMatchPart MatchPartGetter) []*MatchResult {
	var results = make([]*MatchResult, 0)
	rules, ok := f.Rules[service]
	if !ok {
		gologger.Debug().Msgf("No rules found for %s", service)
		return results
	}
	// 对每个规则进行匹配
	for _, rule := range rules {
		ok, extract := rule.Match(getMatchPart)
		if ok {
			results = append(results, &MatchResult{
				Rule:      rule,
				Extracted: extract,
			})
		}
	}
	return results
}

func NewFinger() *Finger {
	return &Finger{Rules: make(map[string][]*Rule)}
}

func (r *Rule) Match(getMatchPart MatchPartGetter) (bool, map[string]string) {
	var matchedString []string
	matchedMapString := make(map[string]string)
	// 为了保证数据都被提取到 所以需要匹配所有的规则
	var matched bool
	var ok bool
	for _, matcher := range r.Matchers {
		if matched && !matcher.HasExtra {
			continue
		}
		caseSensitive := matcher.CaseSensitive
		switch matcher.GetType() {
		case matchers.StatusMatcher:
			code := getMatchPart(matcher.Part, caseSensitive)
			statusCode, _ := strconv.Atoi(code)
			matched = matcher.MatchStatusCode(statusCode)
		case matchers.SizeMatcher:
			matched = false
		case matchers.WordsMatcher:
			matched, matchedString = matcher.MatchWords(getMatchPart(matcher.Part, caseSensitive))
		case matchers.RegexMatcher:
			matched, matchedString = matcher.MatchRegex(getMatchPart(matcher.Part, caseSensitive))
		default:
			panic("unhandled default case:" + matcher.GetType().String() + " for name: " + r.Name)
		}
		if matcher.Name != "" && len(matchedString) > 0 {
			matchedMapString[matcher.Name] = matchedString[0]
		}
		if matcher.Cpe != nil {
			// merge
			for k, v := range matcher.Cpe {
				// 判断是否存在
				if _, ex := matchedMapString[k]; !ex {
					matchedMapString[k] = v
				}
			}
		}
		if matched {
			ok = true
			continue
		}
		if r.MatchersCondition == "and" {
			return false, nil
		}
	}
	return ok, matchedMapString
}
