package api

import (
	"strings"
	"testing"
)

func TestSanitizeURL(t *testing.T) {
	longPath := "https://github.com/owner/" + strings.Repeat("a", 256)

	tests := []struct {
		name       string
		input      string
		wantClean  string
		wantErrSub string
	}{
		// Accept
		{"plain", "https://github.com/owner/repo", "https://github.com/owner/repo", ""},
		{"with .git", "https://github.com/owner/repo.git", "https://github.com/owner/repo.git", ""},
		{"trailing slash", "https://github.com/owner/repo/", "https://github.com/owner/repo/", ""},
		{"dots hyphens underscores", "https://github.com/my-org_1/repo.name-v2", "https://github.com/my-org_1/repo.name-v2", ""},

		// Length
		{"too long", longPath, "", "too long"},

		// Non-ASCII (Cyrillic 'о' at end)
		{"non-ascii", "https://github.com/owner/repо", "", "invalid characters"},

		// Null byte
		{"null byte", "https://github.com/owner/repo\x00", "", "invalid characters"},

		// Scheme
		{"http scheme", "http://github.com/a/b", "", "HTTPS"},
		{"ssh scheme", "ssh://github.com/a/b", "", "HTTPS"},
		{"file scheme", "file:///etc/passwd", "", "HTTPS"},

		// Host
		{"lookalike suffix", "https://github.com.evil.com/a/b", "", "github.com"},
		{"different host", "https://gitlab.com/a/b", "", "github.com"},
		{"subdomain", "https://raw.githubusercontent.com/a/b", "", "github.com"},
		{"ip host", "https://140.82.121.4/a/b", "", "github.com"},

		// Credentials
		{"userinfo", "https://user:pass@github.com/a/b", "", "credentials"},

		// Query / fragment
		{"query", "https://github.com/a/b?x=1", "", "query parameters or fragments"},
		{"fragment", "https://github.com/a/b#frag", "", "query parameters or fragments"},

		// Path traversal
		{"traversal", "https://github.com/a/../b", "", "invalid path"},

		// Final regex
		{"too many segments", "https://github.com/a/b/c", "", "invalid GitHub URL"},
		{"missing repo", "https://github.com/a", "", "invalid GitHub URL"},
		{"empty segment", "https://github.com//b", "", "invalid GitHub URL"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			clean, errMsg := sanitizeURL(tc.input)

			if tc.wantErrSub == "" {
				if errMsg != "" {
					t.Fatalf("expected success, got error %q", errMsg)
				}
				if clean != tc.wantClean {
					t.Fatalf("clean = %q, want %q", clean, tc.wantClean)
				}
				return
			}

			if errMsg == "" {
				t.Fatalf("expected error containing %q, got success with clean=%q", tc.wantErrSub, clean)
			}
			if !strings.Contains(errMsg, tc.wantErrSub) {
				t.Fatalf("error = %q, want substring %q", errMsg, tc.wantErrSub)
			}
		})
	}
}
