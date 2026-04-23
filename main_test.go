package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

// buildRateLimitedRouter wires rateLimiter(cfg) in front of a stub handler
// that increments *reached each time the request gets through. Returns the
// router and a pointer to the counter.
func buildRateLimitedRouter(cfg Config) (*gin.Engine, *int) {
	reached := 0
	r := gin.New()
	r.POST("/test", rateLimiter(cfg), func(c *gin.Context) {
		reached++
		c.Status(http.StatusOK)
	})
	return r, &reached
}

// sendFrom sends a POST /test with the given client IP in RemoteAddr.
// gin's ClientIP() falls back to RemoteAddr when no X-Forwarded-For is present.
func sendFrom(r *gin.Engine, ip string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/test", nil)
	req.RemoteAddr = ip + ":1234"
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func TestRateLimiter(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("under limit: all requests reach handler", func(t *testing.T) {
		r, reached := buildRateLimitedRouter(Config{RateLimit: 3, RateWindowSecs: 60})
		for range 3 {
			w := sendFrom(r, "1.1.1.1")
			if w.Code != http.StatusOK {
				t.Fatalf("got status %d, want 200 (body=%q)", w.Code, w.Body.String())
			}
		}
		if *reached != 3 {
			t.Fatalf("handler reached %d times, want 3", *reached)
		}
	})

	t.Run("over limit: 4th request returns 429 and does not reach handler", func(t *testing.T) {
		r, reached := buildRateLimitedRouter(Config{RateLimit: 3, RateWindowSecs: 60})
		for range 3 {
			sendFrom(r, "1.1.1.1")
		}
		w := sendFrom(r, "1.1.1.1")
		if w.Code != http.StatusTooManyRequests {
			t.Fatalf("got status %d, want 429 (body=%q)", w.Code, w.Body.String())
		}
		if *reached != 3 {
			t.Fatalf("handler reached %d times, want 3 (4th must not reach)", *reached)
		}
	})

	t.Run("independent IPs have separate counters", func(t *testing.T) {
		r, reached := buildRateLimitedRouter(Config{RateLimit: 3, RateWindowSecs: 60})
		for range 3 {
			sendFrom(r, "1.1.1.1")
		}
		// 1.1.1.1 exhausted. A new IP should still pass.
		w := sendFrom(r, "2.2.2.2")
		if w.Code != http.StatusOK {
			t.Fatalf("different IP: got status %d, want 200 (body=%q)", w.Code, w.Body.String())
		}
		if *reached != 4 {
			t.Fatalf("handler reached %d times, want 4 (3 from first IP + 1 from second)", *reached)
		}
	})

	t.Run("window rolls over after expiration", func(t *testing.T) {
		r, reached := buildRateLimitedRouter(Config{RateLimit: 2, RateWindowSecs: 1})
		for range 2 {
			sendFrom(r, "1.1.1.1")
		}
		// 3rd within the 1-second window → blocked.
		if w := sendFrom(r, "1.1.1.1"); w.Code != http.StatusTooManyRequests {
			t.Fatalf("3rd in-window: got %d, want 429", w.Code)
		}
		// Wait past window. The handler checks `now.Sub(windowStart) > window`
		// (strictly greater), so 1100ms clears it with margin for timer jitter.
		time.Sleep(1100 * time.Millisecond)
		if w := sendFrom(r, "1.1.1.1"); w.Code != http.StatusOK {
			t.Fatalf("after window: got %d, want 200", w.Code)
		}
		if *reached != 3 {
			t.Fatalf("handler reached %d times, want 3 (2 before rollover + 1 after)", *reached)
		}
	})
}
