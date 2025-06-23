// Package cleanhttp provides matching for HTTP based wildcards
// hosts related to WAF, CDN etc similar to cdncheck.
package cleanhttp

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"slices"
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
	RequestURL string
}

// CheckRedirect represents redirect checking configuration
type CheckRedirect struct {
	SourcePorts        []int `json:"source_ports"`
	TargetPorts        []int `json:"target_ports"`
	RedirectToRootHost bool  `json:"redirect_to_root_host"`
}

// RuleJSON represents the JSON structure for loading rules
type RuleJSON struct {
	HTTPStatusCode string            `json:"http_status_code,omitempty"`
	HTTPHeader     map[string]string `json:"http_header,omitempty"`
	HTTPBody       []string          `json:"http_body,omitempty"`
	HTTPBodyRegex  []string          `json:"http_body_regex,omitempty"`
	HTTPTitle      string            `json:"http_title,omitempty"`
	CheckRedirect  *CheckRedirect    `json:"check_redirect,omitempty"`
}

// ServicesJSON represents the root JSON structure
type ServicesJSON struct {
	Services map[string]RuleJSON `json:"services"`
}

// Rule contains the compiled patterns for matching
type Rule struct {
	StatusMin     int
	StatusMax     int
	Headers       map[string]string
	BodyContains  []string
	BodyRegex     []*regexp.Regexp
	TitleExact    string
	RedirectCheck *CheckRedirect
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

func (m *Matcher) AddRules(data []byte) error {
	var servicesJSON ServicesJSON
	if err := json.Unmarshal(data, &servicesJSON); err != nil {
		return fmt.Errorf("parsing rules JSON: %w", err)
	}

	for provider, jsonRule := range servicesJSON.Services {
		ruleCompiled, err := compileRule(jsonRule)
		if err != nil {
			return fmt.Errorf("compiling rule for %s: %w", provider, err)
		}
		m.rules[provider] = ruleCompiled
	}
	return nil
}

// compileRule converts a JSON rule into a compiled Rule
func compileRule(jr RuleJSON) (Rule, error) {
	rule := Rule{
		Headers:       make(map[string]string),
		BodyContains:  jr.HTTPBody,
		TitleExact:    jr.HTTPTitle,
		RedirectCheck: jr.CheckRedirect,
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
	loweredHeaders := make(map[string]string)
	for k, v := range resp.Headers {
		loweredHeaders[strings.ToLower(k)] = v
	}
	resp.Headers = loweredHeaders

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

	// Redirect check
	if rule.RedirectCheck != nil {
		if !matchRedirectRule(resp, *rule.RedirectCheck) {
			return false
		}
	}

	return true
}

// matchRedirectRule checks if a response matches redirect rules
func matchRedirectRule(resp Response, redirectRule CheckRedirect) bool {
	parsedOriginalURL, err := url.Parse(resp.RequestURL)
	if err != nil {
		return false
	}
	originalPort := getPortFromURL(parsedOriginalURL)

	if !slices.Contains(redirectRule.SourcePorts, originalPort) {
		return false
	}

	location, exists := resp.Headers["location"]
	if !exists {
		return false
	}

	parsedLocation, err := url.Parse(location)
	if err != nil {
		return false
	}

	if !parsedLocation.IsAbs() {
		parsedLocation.Scheme = parsedOriginalURL.Scheme
		parsedLocation.Host = parsedOriginalURL.Host
	}

	if redirectRule.RedirectToRootHost {
		if parsedLocation.Path != "/" && parsedLocation.Path != "" {
			return false
		}
	}
	targetPort := getPortFromURL(parsedLocation)
	return slices.Contains(redirectRule.TargetPorts, targetPort)
}

// getPortFromURL extracts port from URL, returning default ports for schemes if not specified
func getPortFromURL(u *url.URL) int {
	port := u.Port()
	if port != "" {
		if p, err := strconv.Atoi(port); err == nil {
			return p
		}
	}

	switch u.Scheme {
	case "https":
		return 443
	case "http":
		return 80
	default:
		return 0
	}
}
