package api

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/bl4ckw1ng/secret-scanner/models"
	"github.com/bl4ckw1ng/secret-scanner/scanner"
	"github.com/gin-gonic/gin"
)

const (
	scanTimeout = 5 * time.Minute
	maxURLLen   = 256
	maxBodySize = 1024 // 1 KB — a repo_url JSON doesn't need more

	// maxConcurrentScans bounds how many scans may run at the same time
	// across the whole process. Each in-flight scan can hold up to
	// maxCloneSize on disk plus regex CPU, so this is the integration point
	// that turns the per-scan caps into a global resource ceiling
	// (concurrency × maxCloneSize ≈ peak /tmp).
	maxConcurrentScans = 3

	// scanQueueWait is how long an incoming request will wait for an
	// in-flight scan to release a slot before giving up with 503. Short
	// enough that waiters don't accumulate under sustained overload, long
	// enough to absorb the common case of a scan finishing within seconds.
	scanQueueWait = 10 * time.Second
)

// scanSlots is a counting semaphore implemented as a buffered channel.
// A send acquires a slot; a receive releases one. Non-blocking acquire
// (select with default) gives fast-fail behaviour under load.
var scanSlots = make(chan struct{}, maxConcurrentScans)

// githubURLPattern validates GitHub repository URLs after all other checks pass.
var githubURLPattern = regexp.MustCompile(
	`^https://github\.com/[A-Za-z0-9_.\-]+/[A-Za-z0-9_.\-]+(?:\.git)?/?$`,
)

// sanitizeURL validates and cleans the incoming repo URL against injection attacks.
func sanitizeURL(raw string) (string, string) {
	// 1. Length check — no legitimate GitHub URL exceeds this
	if len(raw) > maxURLLen {
		return "", "URL too long"
	}

	// 2. Reject non-ASCII characters (homoglyph / unicode attacks)
	for _, r := range raw {
		if r > unicode.MaxASCII {
			return "", "URL contains invalid characters"
		}
	}

	// 3. Reject null bytes
	if strings.ContainsRune(raw, '\x00') {
		return "", "URL contains invalid characters"
	}

	// 4. Parse as a proper URL — catches malformed schemes, encoded tricks
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", "invalid URL format"
	}

	// 5. Scheme must be exactly https
	if parsed.Scheme != "https" {
		return "", "only HTTPS URLs are allowed"
	}

	// 6. Host must be exactly github.com — blocks IP addresses, subdomains, lookalikes
	if parsed.Host != "github.com" {
		return "", "only github.com repositories are supported"
	}

	// 7. No userinfo (user:pass@github.com)
	if parsed.User != nil {
		return "", "URL must not contain credentials"
	}

	// 8. No query params or fragments — not valid for git clone
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", "URL must not contain query parameters or fragments"
	}

	// 9. Path traversal check on the decoded path
	if strings.Contains(parsed.Path, "..") {
		return "", "URL contains invalid path"
	}

	// 10. Reconstruct a clean URL from parsed components (strips encoded tricks)
	clean := "https://github.com" + parsed.Path

	// 11. Final regex check on the clean URL
	if !githubURLPattern.MatchString(clean) {
		return "", "invalid GitHub URL"
	}

	return clean, ""
}

// ScanHandler handles POST /api/scan
func ScanHandler(c *gin.Context) {
	// Limit request body size
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxBodySize)

	var req models.ScanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "request body must contain repo_url"})
		return
	}

	repoURL, validationErr := sanitizeURL(strings.TrimSpace(req.RepoURL))
	if validationErr != "" {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: validationErr})
		return
	}

	displayURL := strings.TrimSuffix(repoURL, ".git")
	displayURL = strings.TrimSuffix(displayURL, "/")

	// Acquire a scan slot, waiting up to scanQueueWait. Done after cheap
	// validation so invalid requests don't burn capacity, but before any
	// expensive work (clone, scan) is started. The wait sub-context is
	// derived from the request context so a client disconnect releases the
	// waiter immediately instead of holding a goroutine for the full wait.
	waitCtx, waitCancel := context.WithTimeout(c.Request.Context(), scanQueueWait)
	select {
	case scanSlots <- struct{}{}:
		waitCancel()
		defer func() { <-scanSlots }()
	case <-waitCtx.Done():
		waitCancel()
		c.JSON(http.StatusServiceUnavailable, models.ErrorResponse{
			Error: "scanner busy, please retry shortly",
		})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), scanTimeout)
	defer cancel()

	result, err := scanner.Scan(ctx, repoURL)
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) || strings.Contains(err.Error(), "timeout") {
			c.JSON(http.StatusRequestTimeout, models.ErrorResponse{Error: "scan timeout"})
			return
		}
		errMsg := err.Error()
		if isNotFound(errMsg) {
			c.JSON(http.StatusNotFound, models.ErrorResponse{Error: "repository not found or private"})
			return
		}
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{Error: "internal scan error"})
		return
	}

	findings := result.Findings
	if findings == nil {
		findings = []models.Finding{}
	}

	resp := models.ScanResponse{
		RepoURL:   displayURL,
		ScannedAt: time.Now().UTC(),
		Stats: models.ScanStats{
			TotalCommitsScanned: result.TotalCommitsScanned,
			TotalFilesScanned:   result.TotalFilesScanned,
			TotalFindings:       len(findings),
		},
		Findings: findings,
	}

	c.JSON(http.StatusOK, resp)
}

// HealthHandler handles GET /health
func HealthHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// isNotFound checks if the error message indicates the repo is missing or private.
func isNotFound(msg string) bool {
	lower := strings.ToLower(msg)
	indicators := []string{
		"repository not found",
		"not found",
		"authentication required",
		"401",
		"404",
		"remote repository is empty",
		"no such host",
		"could not read",
	}
	for _, ind := range indicators {
		if strings.Contains(lower, ind) {
			return true
		}
	}
	return false
}
