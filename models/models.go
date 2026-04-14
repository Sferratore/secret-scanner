package models

import "time"

// ScanRequest is the incoming POST body.
type ScanRequest struct {
	RepoURL string `json:"repo_url" binding:"required"`
}

// ScanStats summarises the scan.
type ScanStats struct {
	TotalCommitsScanned int `json:"total_commits_scanned"`
	TotalFilesScanned   int `json:"total_files_scanned"`
	TotalFindings       int `json:"total_findings"`
}

// Finding represents a single detected secret.
type Finding struct {
	ID            string    `json:"id"`
	Type          string    `json:"type"`
	Severity      string    `json:"severity"`
	Description   string    `json:"description"`
	File          string    `json:"file"`
	Line          int       `json:"line"`
	Commit        string    `json:"commit"`
	CommitMessage string    `json:"commit_message"`
	CommitAuthor  string    `json:"commit_author"`
	CommitDate    time.Time `json:"commit_date"`
	MatchedValue  string    `json:"matched_value"`
	Context       string    `json:"context"`
}

// ScanResponse is the full API response.
type ScanResponse struct {
	RepoURL   string    `json:"repo_url"`
	ScannedAt time.Time `json:"scanned_at"`
	Stats     ScanStats `json:"stats"`
	Findings  []Finding `json:"findings"`
}

// ErrorResponse wraps error messages.
type ErrorResponse struct {
	Error string `json:"error"`
}
