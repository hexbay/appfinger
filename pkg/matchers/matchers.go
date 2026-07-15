package matchers

import "regexp"

type ConditionType int

const (
	ANDCondition ConditionType = iota + 1
	ORCondition
)

type Matcher struct {
	Name      string            `json:"name,omitempty"`
	Type      MatcherTypeHolder `yaml:"type" json:"type"`
	Words     []string          `yaml:"words" json:"words,omitempty"`
	Part      string            `yaml:"part" json:"part,omitempty"`
	Regex     []string          `yaml:"regex" json:"regex,omitempty"`
	Encoding  string            `yaml:"encoding" json:"encoding,omitempty"`
	MatchAll  bool              `yaml:"matchAll" json:"match_all,omitempty"`
	Condition string            `yaml:"condition" json:"condition,omitempty"`
	Group     int               `yaml:"group"`
	Status    []int             `yaml:"status,omitempty" jsonschema:"title=status to match,description=Status to match for the response" json:"status,omitempty"`
	// CaseInsensitive bool              `yaml:"case-insensitive,omitempty" json:"case-insensitive,omitempty" jsonschema:"title=use case insensitive match,description=use case insensitive match"`
	// 指纹匹配中 忽略大小写的概率比较多,所以默认忽略大小写 使用CaseSensitive 更合理
	CaseSensitive bool `yaml:"case-sensitive,omitempty" json:"case-sensitive,omitempty" jsonschema:"title=use case sensitive match,description=use case sensitive match"`
	Negative      bool `yaml:"negative,omitempty" json:"negative,omitempty" jsonschema:"title=negative specifies if match reversed,description=Negative specifies if the match should be reversed"`
	regexCompiled []*regexp.Regexp
	condition     ConditionType
	matcherType   MatcherType
	HasExtra      bool
	Cpe           map[string]string `yaml:"cpe" json:"cpe,omitempty"`
}

var ConditionTypes = map[string]ConditionType{
	"and": ANDCondition,
	"or":  ORCondition,
}
