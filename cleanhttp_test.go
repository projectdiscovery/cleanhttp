package cleanhttp

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMatcher(t *testing.T) {
	// Initialize matcher with default rules
	matcher, err := NewMatcher("")
	if err != nil {
		t.Fatalf("Failed to create matcher: %v", err)
	}

	tests := []struct {
		name     string
		response Response
		want     []string
	}{
		{
			name: "cloudflare match",
			response: Response{
				StatusCode: 503,
				Headers:    map[string]string{"server": "cloudflare"},
				Body:       "error code: 1020",
			},
			want: []string{"cloudflare"},
		},
		{
			name: "cloudflare no match - missing header",
			response: Response{
				StatusCode: 503,
				Headers:    map[string]string{"server": "nginx"},
				Body:       "error code: 1020",
			},
			want: nil,
		},
		{
			name: "cloudflare redirect match",
			response: Response{
				StatusCode: 301,
				Headers: map[string]string{
					"server":                 "cloudflare",
					"location":               "https://example.com/",
					"x-original-request-url": "https://example.com:2052/",
				},
			},
			want: []string{"cloudflare_redirection"},
		},
		{
			name: "cloudflare redirect - wrong source port",
			response: Response{
				StatusCode: 301,
				Headers: map[string]string{
					"server":                 "cloudflare",
					"location":               "https://example.com/",
					"x-original-request-url": "https://example.com:9999/",
				},
			},
			want: nil,
		},
		{
			name: "cloudflare redirect - wrong target port",
			response: Response{
				StatusCode: 301,
				Headers: map[string]string{
					"server":                 "cloudflare",
					"location":               "https://example.com:8080/",
					"x-original-request-url": "https://example.com:2052/",
				},
			},
			want: nil,
		},
		{
			name: "cloudflare redirect - not to root",
			response: Response{
				StatusCode: 301,
				Headers: map[string]string{
					"server":                 "cloudflare",
					"location":               "https://example.com/path",
					"x-original-request-url": "https://example.com:2052/",
				},
			},
			want: nil,
		},
		{
			name: "cloudflare redirect - different host",
			response: Response{
				StatusCode: 301,
				Headers: map[string]string{
					"server":                 "cloudflare",
					"location":               "https://different.com/",
					"x-original-request-url": "https://example.com:2052/",
				},
			},
			want: nil,
		},
		{
			name: "akamai match",
			response: Response{
				StatusCode: 400,
				Title:      "Invalid URL",
				Body:       "The requested URL \"[no URL]\", is invalid.",
				Headers: map[string]string{
					"server": "AkamaiGHost",
				},
			},
			want: []string{"akamai"},
		},
		{
			name: "akamai no match - wrong title",
			response: Response{
				StatusCode: 400,
				Title:      "Not Found",
				Body:       "The requested URL /test.php is invalid",
				Headers: map[string]string{
					"server": "AkamaiGHost",
				},
			},
			want: nil,
		},
		{
			name: "no matches",
			response: Response{
				StatusCode: 200,
				Headers:    map[string]string{"server": "nginx"},
				Title:      "Welcome",
				Body:       "Hello, World!",
			},
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matcher.Match(tt.response)
			require.ElementsMatch(t, got, tt.want, "could not match %v", tt.response)
		})
	}
}

func TestNewMatcherErrors(t *testing.T) {
	tests := []struct {
		name    string
		rules   string
		wantErr bool
	}{
		{
			name:    "non-existent file",
			rules:   "nonexistent.json",
			wantErr: true,
		},
		{
			name:    "default rules",
			rules:   "",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewMatcher(tt.rules)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewMatcher() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
