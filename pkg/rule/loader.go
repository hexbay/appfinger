package rule

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/projectdiscovery/gologger"
	"gopkg.in/yaml.v3"
)

func checkIsRuleFile(filename string) bool {
	if len(filename) > 0 && filename[0] == '.' {
		return false
	}
	return strings.HasSuffix(filename, ".yaml") || strings.HasSuffix(filename, ".yml")
}

func ScanRuleDirectory(directory string) (*RuleSet, error) {
	group := NewRuleSet()
	// 判断是文件名还是目录
	file, err := os.Stat(directory)
	if err != nil {
		return nil, err
	}
	if file.IsDir() {
		//	scan (runtime loader: 遇到单个文件错误时仅记录日志并继续)
		_ = walkRuleFiles(directory, func(path string, info os.FileInfo) error {
			rules, err := LoadRule(path)
			if err != nil {
				gologger.Warning().Msgf("LoadRule Error: %s -> %v", info.Name(), err.Error())
				// 运行模式下，单个规则文件有问题时跳过该文件，继续处理其他文件
				return nil
			}
			group.AddRules(rules)
			return nil
		})
	} else {
		// 单个文件
		rules, err := LoadRule(directory)
		if err != nil {
			return nil, err
		}
		group.AddRules(rules)
	}
	return group, nil
}

// walkRuleFiles 遍历指定目录下所有规则文件（*.yaml / *.yml），
// 会跳过隐藏目录（.git、.github 等），对每个规则文件调用 visit 回调。
func walkRuleFiles(root string, visit func(path string, info os.FileInfo) error) error {
	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		// 隐藏目录（.git、.github 等）直接跳过
		if info.IsDir() && isHiddenDir(info) {
			return filepath.SkipDir
		}
		// 只对规则文件调用回调
		if !info.IsDir() && checkIsRuleFile(info.Name()) {
			return visit(path, info)
		}
		return nil
	})
}

// shouldSkipDir 判断在遍历规则目录时是否应跳过某个子目录。
// 规则：
// - 只处理目录
// - 不跳过根目录本身
// - 对于子目录，如果名称以 '.' 开头且不是 '.' 或 '..'，则视为隐藏目录并跳过
func isHiddenDir(info os.FileInfo) bool {
	name := info.Name()
	// 排除特殊目录项
	if name == "." || name == ".." {
		return false
	}
	// 所有以 '.' 开头的子目录视为隐藏目录（例如 .git、.github、.idea 等）
	if strings.HasPrefix(name, ".") {
		return true
	}
	return false
}

// isValidMatcherPart checks whether the specified matcher part is supported by
// the runtime banner adapter used by the scanner package.
//
// Supported values:
//   - "" (will be normalized to body)
//   - "body"
//   - "url"
//   - "header"
//   - "cert"
//   - "title"
//   - "response"
//   - "icon_hash"
//   - "body_hash"
//   - "server"
//   - "headers.<header-name>" (e.g. headers.server, headers.content-type)
func isValidMatcherPart(part string) bool {
	if part == "" || part == "body" {
		return true
	}
	if strings.HasPrefix(part, "headers.") {
		return true
	}
	switch part {
	case "url", "header", "cert", "title", "response", "icon_hash", "body_hash", "server":
		return true
	}
	return false
}

// LoadRuleStrict 与 LoadRule 类似，但用于严格校验：
// - 收集 YAML 解析错误
// - 收集 matcher 编译错误
// 返回规则和累积错误（如果有）。
func LoadRuleStrict(filename string) ([]*Rule, []error) {
	var allErrs []error
	content, err := os.ReadFile(filename)
	if err != nil {
		allErrs = append(allErrs, fmt.Errorf("read file failed: %w", err))
		return nil, allErrs
	}
	var rules []*Rule
	err = yaml.Unmarshal(content, &rules)
	if err != nil {
		allErrs = append(allErrs, fmt.Errorf("yaml unmarshal failed: %w", err))
		return nil, allErrs
	}
	for _, rule := range rules {
		for _, matcher := range rule.Matchers {
			if matcher == nil {
				allErrs = append(allErrs, fmt.Errorf("rule %s has nil matcher", rule.Name))
				continue
			}
			if err := matcher.CompileMatchers(); err != nil {
				allErrs = append(allErrs, fmt.Errorf("compile matcher failed for rule %s: %w", rule.Name, err))
				continue
			}
			// 业务规范校验：part 必须在支持的枚举范围内
			if !isValidMatcherPart(matcher.Part) {
				allErrs = append(allErrs, fmt.Errorf("invalid matcher part '%s' for rule %s", matcher.Part, rule.Name))
			}
		}
	}
	return rules, allErrs
}

// ValidateRuleDirectory 严格验证规则目录下的所有规则文件。
//
// 行为：
// - 遍历目录中的所有 YAML 规则文件
// - 对每个文件调用 LoadRuleStrict 收集 YAML/Matcher 的所有错误
// - 不会中断整个遍历，所有问题都会被返回
//
// fatalErr 仅在目录本身不可访问等致命场景下返回；
// errs 列出所有规则文件级别的问题，用于 validate 模式报告。
func ValidateRuleDirectory(directory string) (errs []error, fatalErr error) {
	file, err := os.Stat(directory)
	if err != nil {
		return nil, fmt.Errorf("stat directory failed: %w", err)
	}
	if file.IsDir() {
		walkErr := walkRuleFiles(directory, func(path string, info os.FileInfo) error {
			_, fileErrs := LoadRuleStrict(path)
			for _, e := range fileErrs {
				// 包装上文件名信息
				errs = append(errs, fmt.Errorf("%s: %w", path, e))
			}
			return nil
		})
		if walkErr != nil {
			return errs, walkErr
		}
		return errs, nil
	}
	// 单文件场景
	_, fileErrs := LoadRuleStrict(directory)
	for _, e := range fileErrs {
		errs = append(errs, fmt.Errorf("%s: %w", directory, e))
	}
	return errs, nil
}
func LoadRule(filename string) ([]*Rule, error) {
	content, err := os.ReadFile(filename)
	if err != nil {
		gologger.Warning().Msgf("ReadFile Error:%v", err.Error())
		return nil, err
	}
	var rules []*Rule
	err = yaml.Unmarshal(content, &rules)
	if err != nil {
		return nil, err
	}
	for _, rule := range rules {
		for _, matcher := range rule.Matchers {
			err := matcher.CompileMatchers()
			if err != nil {
				gologger.Error().Msgf("%s Compile matcher:%s -> %s", filename, err.Error(), rule.Name)
				continue
			}
		}
	}
	return rules, nil

}
