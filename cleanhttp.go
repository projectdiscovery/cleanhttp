// Package cleanhttp provides matching for HTTP based wildcards
// hosts related to WAF, CDN etc similar to cdncheck.
package cleanhttp

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
)

//go:embed rules.json
var defaultRules []byte

// Response contains the HTTP response data to match against
type Response struct {
	StatusCode int
	Headers    map[string]string
	Body       string
	Title      string
}

// RuleJSON represents the JSON structure for loading rules
type RuleJSON struct {
	HTTPStatusCode string            `json:"http_status_code,omitempty"`
	HTTPHeader     map[string]string `json:"http_header,omitempty"`
	HTTPBody       []string          `json:"http_body,omitempty"`
	HTTPBodyRegex  []string          `json:"http_body_regex,omitempty"`
	HTTPTitle      string            `json:"http_title,omitempty"`
}

// ServicesJSON represents the root JSON structure
type ServicesJSON struct {
	Services map[string]RuleJSON `json:"services"`
}

// Rule contains the compiled patterns for matching
type Rule struct {
	StatusMin    int
	StatusMax    int
	Headers      map[string]string
	BodyContains []string
	BodyRegex    []*regexp.Regexp
	TitleExact   string
}

// Matcher handles the WAF/CDN detection rules
type Matcher struct {
	rules map[string]Rule
}

// NewMatcher creates a Matcher instance with compiled rules from JSON
func NewMatcher(rulesPath string) (*Matcher, error) {
	var data []byte
	var err error

	if rulesPath == "" {
		data = defaultRules
	} else {
		data, err = os.ReadFile(rulesPath)
		if err != nil {
			return nil, fmt.Errorf("reading rules file: %w", err)
		}
	}

	var servicesJSON ServicesJSON
	if err := json.Unmarshal(data, &servicesJSON); err != nil {
		return nil, fmt.Errorf("parsing rules JSON: %w", err)
	}

	rules := make(map[string]Rule)
	for provider, jsonRule := range servicesJSON.Services {
		rule, err := compileRule(jsonRule)
		if err != nil {
			return nil, fmt.Errorf("compiling rule for %s: %w", provider, err)
		}
		rules[provider] = rule
	}

	return &Matcher{rules: rules}, nil
}

// compileRule converts a JSON rule into a compiled Rule
func compileRule(jr RuleJSON) (Rule, error) {
	rule := Rule{
		Headers:      make(map[string]string),
		BodyContains: jr.HTTPBody,
		TitleExact:   jr.HTTPTitle,
	}
	for k, v := range jr.HTTPHeader {
		rule.Headers[strings.ToLower(k)] = v
	}

	// Parse status code (single or range)
	if jr.HTTPStatusCode != "" {
		parts := strings.Split(jr.HTTPStatusCode, "-")
		switch len(parts) {
		case 1:
			// Single status code
			if status, err := strconv.Atoi(parts[0]); err == nil {
				rule.StatusMin = status
				rule.StatusMax = status
			}
		case 2:
			// Status code range
			min, _ := strconv.Atoi(parts[0])
			max, _ := strconv.Atoi(parts[1])
			if min > 0 && max > 0 {
				rule.StatusMin = min
				rule.StatusMax = max
			}
		default:
			return Rule{}, fmt.Errorf("invalid status code format: %s", jr.HTTPStatusCode)
		}
	}

	// Compile body regex patterns
	for _, pattern := range jr.HTTPBodyRegex {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return Rule{}, fmt.Errorf("invalid body regex pattern %q: %w", pattern, err)
		}
		rule.BodyRegex = append(rule.BodyRegex, re)
	}

	return rule, nil
}

// Match returns the names of WAF/CDN providers that match the response
func (m *Matcher) Match(resp Response) []string {
	var matches []string
	for provider, rule := range m.rules {
		if matchRule(resp, rule) {
			matches = append(matches, provider)
		}
	}
	return matches
}

// matchRule checks if a response matches a specific rule
func matchRule(resp Response, rule Rule) bool {
	if rule.StatusMin != 0 && resp.StatusCode < rule.StatusMin {
		return false
	}
	if rule.StatusMax != 0 && resp.StatusCode > rule.StatusMax {
		return false
	}

	// Headers check
	for header, pattern := range rule.Headers {
		value, exists := resp.Headers[header]
		if !exists || !strings.Contains(value, pattern) {
			return false
		}
	}

	// Body contains check
	for _, pattern := range rule.BodyContains {
		if !strings.Contains(resp.Body, pattern) {
			return false
		}
	}

	// Body regex check
	for _, re := range rule.BodyRegex {
		if !re.MatchString(resp.Body) {
			return false
		}
	}

	// Title checks
	if rule.TitleExact != "" && resp.Title != rule.TitleExact {
		return false
	}

	return true
}
