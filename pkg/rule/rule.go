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

// CompiledRule is the runtime representation of a YAML Rule.
// The source Rule is retained for metadata and extraction, while the rule
// set owns only compiled runtime entries.
type CompiledRule struct {
	Source  *Rule
	Runtime *Rule
}

// Finger 根据协议分组
type RuleSet struct {
	rules map[string][]*CompiledRule
}

func (f RuleSet) AddRules(rules []*Rule) {
	for _, rule := range rules {
		if rule.Service == "" {
			rule.Service = "http"
		}
		runtime := cloneRule(rule)
		for _, matcher := range runtime.Matchers {
			_ = matcher.CompileMatchers()
		}
		f.rules[rule.Service] = append(f.rules[rule.Service], &CompiledRule{Source: rule, Runtime: runtime})
	}
}

// Match 执行指纹匹配并返回包含规则的匹配结果
func (f RuleSet) Match(service string, getMatchPart MatchPartGetter) []*MatchResult {
	var results = make([]*MatchResult, 0)
	rules, ok := f.rules[service]
	if !ok {
		gologger.Debug().Msgf("No rules found for %s", service)
		return results
	}
	// 对每个规则进行匹配
	for _, compiled := range rules {
		rule := compiled.Runtime
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

func cloneRule(source *Rule) *Rule {
	clone := *source
	clone.Require = append([]string(nil), source.Require...)
	clone.Matchers = make([]*matchers.Matcher, 0, len(source.Matchers))
	for _, sourceMatcher := range source.Matchers {
		if sourceMatcher == nil {
			clone.Matchers = append(clone.Matchers, nil)
			continue
		}
		matcher := *sourceMatcher
		matcher.Words = append([]string(nil), sourceMatcher.Words...)
		matcher.Regex = append([]string(nil), sourceMatcher.Regex...)
		matcher.Status = append([]int(nil), sourceMatcher.Status...)
		if sourceMatcher.Cpe != nil {
			matcher.Cpe = make(map[string]string, len(sourceMatcher.Cpe))
			for k, v := range sourceMatcher.Cpe {
				matcher.Cpe[k] = v
			}
		}
		clone.Matchers = append(clone.Matchers, &matcher)
	}
	if source.Cpe != nil {
		clone.Cpe = make(map[string]interface{}, len(source.Cpe))
		for k, v := range source.Cpe {
			clone.Cpe[k] = v
		}
	}
	clone.Plugins = append([]*Plugin(nil), source.Plugins...)
	return &clone
}

func NewRuleSet() *RuleSet {
	return &RuleSet{rules: make(map[string][]*CompiledRule)}
}

// CategoryCount returns the number of rule categories in this immutable snapshot.
func (f RuleSet) CategoryCount() int { return len(f.rules) }

// RuleCount returns the total number of compiled rules in this immutable snapshot.
func (f RuleSet) RuleCount() int {
	count := 0
	for _, rules := range f.rules {
		count += len(rules)
	}
	return count
}

// FirstRule returns the first source rule in a category, if present.
func (f RuleSet) FirstRule(name string) *Rule {
	rules := f.rules[name]
	if len(rules) == 0 {
		return nil
	}
	return rules[0].Source
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
		if matcher.Negative {
			matched = !matched
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
