package cli

import (
	"errors"
	"fmt"
	"github.com/logrusorgru/aurora"
	"strings"
)

func formatExtract(extract map[string]map[string]string) string {
	var s []string
	for key, value := range extract {
		var s2 []string
		for v, vv := range value {
			s2 = append(s2, aurora.Blue(fmt.Sprintf("%s=%s", v, vv)).String())
		}
		s = append(s, fmt.Sprintf("%s:{%s}", aurora.Cyan(key).String(), strings.Join(s2, ",")))
	}
	return strings.Join(s, ",")
}
func StringTerms(s string) string {
	return strings.Trim(strings.ReplaceAll(strings.ReplaceAll(s, "\n", ""), "\t", ""), " ")
}

var (
	ErrEmptyInput = errors.New("empty data")
)

func sanitize(data string) (string, error) {
	data = strings.Trim(data, "\n\t\"' ")
	if data == "" {
		return "", ErrEmptyInput
	}
	return data, nil
}
