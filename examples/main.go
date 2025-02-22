package main

import (
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/projectdiscovery/cleanhttp"
)

func main() {
	urls := []string{
		"http://example.com/",
	}

	matcher, err := cleanhttp.NewMatcher("")
	if err != nil {
		fmt.Printf("Error creating matcher: %v\n", err)
		return
	}

	for _, url := range urls {
		resp, err := http.Get(url)
		if err != nil {
			fmt.Printf("Error requesting %s: %v\n", url, err)
			continue
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			fmt.Printf("Error reading body from %s: %v\n", url, err)
			continue
		}

		headers := make(map[string]string)
		for k, v := range resp.Header {
			headers[k] = strings.Join(v, ", ")
		}

		// Extract title using regex for demo
		titleRegex := regexp.MustCompile(`<title[^>]*>([^<]+)</title>`)
		title := ""
		if matches := titleRegex.FindStringSubmatch(string(body)); len(matches) > 1 {
			title = matches[1]
		}

		cleanResp := cleanhttp.Response{
			StatusCode: resp.StatusCode,
			Headers:    headers,
			Body:       string(body),
			Title:      title,
		}

		// Match WAF/CDN providers
		matches := matcher.Match(cleanResp)
		if len(matches) > 0 {
			fmt.Printf("%s -> WAF/CDN detected: %v\n", url, matches)
		} else {
			fmt.Printf("%s -> No WAF/CDN detected\n", url)
		}
	}
}
