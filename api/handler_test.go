package api

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
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

// Builds a JSON body of exactly n bytes by padding the repo_url value with 'x'.
// For n < overhead, returns n whitespace bytes instead.
func bodyOfSize(n int) []byte {
	const prefix = `{"repo_url":"`
	const suffix = `"}`
	overhead := len(prefix) + len(suffix)
	if n < overhead {
		return []byte(strings.Repeat(" ", n))
	}
	return []byte(prefix + strings.Repeat("x", n-overhead) + suffix)
}

func TestScanHandlerBodySizeLimit(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/api/scan", ScanHandler)

	tests := []struct {
		name       string
		body       []byte
		wantStatus int
		wantErrSub string
	}{
		{
			name:       "empty body",
			body:       []byte{},
			wantStatus: http.StatusBadRequest,
			wantErrSub: "request body must contain repo_url",
		},
		{
			name:       "well-formed json under limit, bad host — size gate passes",
			body:       []byte(`{"repo_url":"https://gitlab.com/a/b"}`),
			wantStatus: http.StatusBadRequest,
			wantErrSub: "github.com",
		},
		{
			name:       "exactly at limit (1024 bytes) — size gate still passes",
			body:       bodyOfSize(1024),
			wantStatus: http.StatusBadRequest,
			wantErrSub: "URL too long",
		},
		{
			name:       "over limit (2 KB) — size gate rejects",
			body:       bodyOfSize(2048),
			wantStatus: http.StatusBadRequest,
			wantErrSub: "request body must contain repo_url",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/scan", bytes.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			if w.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d (body=%q)", w.Code, tc.wantStatus, w.Body.String())
			}
			if !strings.Contains(w.Body.String(), tc.wantErrSub) {
				t.Fatalf("response body = %q, want substring %q", w.Body.String(), tc.wantErrSub)
			}
		})
	}

	t.Run("1 MB body rejected quickly (not buffered)", func(t *testing.T) {
		body := bodyOfSize(1024 * 1024)
		req := httptest.NewRequest(http.MethodPost, "/api/scan", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		start := time.Now()
		router.ServeHTTP(w, req)
		elapsed := time.Since(start)

		if w.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400 (body=%q)", w.Code, w.Body.String())
		}
		if !strings.Contains(w.Body.String(), "request body must contain repo_url") {
			t.Fatalf("response body = %q, want size-rejection message", w.Body.String())
		}
		// Soft upper bound — if MaxBytesReader regresses and the body gets
		// fully buffered/parsed, this will blow well past 1s. Generous
		// margin so CI jitter doesn't cause flakes.
		if elapsed > time.Second {
			t.Fatalf("handler took %v, want < 1s (MaxBytesReader may not trip early)", elapsed)
		}
	})
}
