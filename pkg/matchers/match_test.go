package matchers

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestWordANDCondition(t *testing.T) {
	m := &Matcher{condition: ANDCondition, Words: []string{"a", "b"}}

	isMatched, matched := m.MatchWords("a b")
	require.True(t, isMatched, "Could not match words with valid AND condition")
	require.Equal(t, m.Words, matched)

	isMatched, matched = m.MatchWords("b")
	require.False(t, isMatched, "Could match words with invalid AND condition")
	require.Equal(t, []string{}, matched)
}

func TestRegexANDCondition(t *testing.T) {
	m := &Matcher{Type: MatcherTypeHolder{MatcherType: RegexMatcher}, Condition: "and", Regex: []string{"[a-z]{3}", "\\d{2}"}}
	err := m.CompileMatchers()
	require.Nil(t, err)

	isMatched, matched := m.MatchRegex("abc abcd 123")
	require.True(t, isMatched, "Could not match regex with valid AND condition")
	require.Equal(t, []string{"abc", "abc", "12"}, matched)

	isMatched, matched = m.MatchRegex("bc 1")
	require.False(t, isMatched, "Could match regex with invalid AND condition")
	require.Equal(t, []string{}, matched)
}

func TestORCondition(t *testing.T) {
	m := &Matcher{condition: ORCondition, Words: []string{"a", "b"}}

	isMatched, matched := m.MatchWords("a b")
	require.True(t, isMatched, "Could not match valid word OR condition")
	require.Equal(t, []string{"a"}, matched)

	isMatched, matched = m.MatchWords("b")
	require.True(t, isMatched, "Could not match valid word OR condition")
	require.Equal(t, []string{"b"}, matched)

	isMatched, matched = m.MatchWords("c")
	require.False(t, isMatched, "Could match invalid word OR condition")
	require.Equal(t, []string{}, matched)
}

func TestRegexOrCondition(t *testing.T) {
	m := &Matcher{Type: MatcherTypeHolder{MatcherType: RegexMatcher}, Condition: "or", Regex: []string{"[a-z]{3}", "\\d{2}"}}
	err := m.CompileMatchers()
	require.Nil(t, err)

	isMatched, matched := m.MatchRegex("ab 123")
	require.True(t, isMatched, "Could not match valid regex OR condition")
	require.Equal(t, []string{"12"}, matched)

	isMatched, matched = m.MatchRegex("bc 1")
	require.False(t, isMatched, "Could match invalid regex OR condition")
	require.Equal(t, []string{}, matched)
}

func TestHexEncoding(t *testing.T) {
	m := &Matcher{Encoding: "hex", Type: MatcherTypeHolder{MatcherType: WordsMatcher}, Part: "body", Words: []string{"50494e47"}}
	err := m.CompileMatchers()
	require.Nil(t, err, "could not compile matcher")

	isMatched, matched := m.MatchWords("PING")
	require.True(t, isMatched, "Could not match valid Hex condition")
	require.Equal(t, m.Words, matched)
}

func TestCompileMatchersIsIdempotent(t *testing.T) {
	m := &Matcher{Type: MatcherTypeHolder{MatcherType: RegexMatcher}, Regex: []string{"demo"}}
	require.NoError(t, m.CompileMatchers())
	require.NoError(t, m.CompileMatchers())
	matched, _ := m.MatchRegex("demo")
	require.True(t, matched)
}
