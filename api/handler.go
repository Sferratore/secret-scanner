package api

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/bl4ckw1ng/secret-scanner/models"
	"github.com/bl4ckw1ng/secret-scanner/scanner"
	"github.com/gin-gonic/gin"
)

const scanTimeout = 5 * time.Minute

// githubURLPattern validates GitHub repository URLs.
var githubURLPattern = regexp.MustCompile(
	`^https://github\.com/[A-Za-z0-9_.\-]+/[A-Za-z0-9_.\-]+(?:\.git)?/?$`,
)

// ScanHandler handles POST /api/scan
func ScanHandler(c *gin.Context) {
	var req models.ScanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "request body must contain repo_url"})
		return
	}

	repoURL := strings.TrimSpace(req.RepoURL)
	// Strip trailing .git for display, keep it for cloning
	displayURL := strings.TrimSuffix(repoURL, ".git")
	displayURL = strings.TrimSuffix(displayURL, "/")

	if !githubURLPattern.MatchString(repoURL) {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Error: "invalid GitHub URL"})
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
