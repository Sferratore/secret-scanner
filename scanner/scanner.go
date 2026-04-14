package scanner

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/bl4ckw1ng/secret-scanner/models"
	"github.com/google/uuid"
)

// dedupeKey uniquely identifies a secret so we don't report duplicates.
type dedupeKey struct {
	patternID string
	masked    string
	file      string
}

// ScanResult holds all findings and statistics from a scan.
type ScanResult struct {
	Findings            []models.Finding
	TotalCommitsScanned int
	TotalFilesScanned   int
}

// Scan clones repoURL and scans its full history and HEAD tree.
func Scan(ctx context.Context, repoURL string) (*ScanResult, error) {
	cloneResult, err := CloneRepo(ctx, repoURL)
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(cloneResult.TmpDir)

	entries, commitCount, err := WalkHistory(ctx, cloneResult)
	if err != nil {
		return nil, err
	}

	seen := make(map[dedupeKey]bool)
	var findings []models.Finding
	filesSeen := make(map[string]bool)

	for _, entry := range entries {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("scan timeout exceeded")
		default:
		}

		filesSeen[entry.Path] = true
		entryFindings := scanContent(entry, seen)
		findings = append(findings, entryFindings...)
	}

	return &ScanResult{
		Findings:            findings,
		TotalCommitsScanned: commitCount,
		TotalFilesScanned:   len(filesSeen),
	}, nil
}

// scanContent runs all patterns against a single FileEntry.
func scanContent(entry FileEntry, seen map[dedupeKey]bool) []models.Finding {
	lines := strings.Split(string(entry.Content), "\n")
	var findings []models.Finding

	commitDate, _ := entry.CommitDate.(time.Time)

	for lineIdx, line := range lines {
		for _, pattern := range Patterns {
			matches := pattern.Regex.FindAllStringSubmatchIndex(line, -1)
			for _, match := range matches {
				// Extract the captured group (subgroup 1 if present, otherwise full match)
				start, end := match[0], match[1]
				if len(match) >= 4 && match[2] >= 0 {
					start, end = match[2], match[3]
				}

				raw := line[start:end]
				if len(raw) == 0 {
					continue
				}

				// Skip placeholders
				if IsPlaceholder(raw) {
					continue
				}

				masked := maskSecret(raw)
				key := dedupeKey{patternID: pattern.ID, masked: masked, file: entry.Path}
				if seen[key] {
					continue
				}
				seen[key] = true

				contextStr := extractContext(lines, lineIdx)

				findings = append(findings, models.Finding{
					ID:            uuid.New().String(),
					Type:          pattern.Type,
					Severity:      pattern.Severity,
					Description:   pattern.Description,
					File:          entry.Path,
					Line:          lineIdx + 1,
					Commit:        entry.CommitHash,
					CommitMessage: truncate(entry.CommitMessage, 120),
					CommitAuthor:  entry.CommitAuthor,
					CommitDate:    commitDate,
					MatchedValue:  masked,
					Context:       contextStr,
				})
			}
		}
	}

	return findings
}

// maskSecret replaces the middle of a secret with asterisks.
// Shows first 4 and last 4 characters; for short values, masks entirely.
func maskSecret(s string) string {
	runes := []rune(s)
	n := len(runes)
	if n <= 8 {
		return strings.Repeat("*", n)
	}
	prefix := string(runes[:4])
	suffix := string(runes[n-4:])
	masked := strings.Repeat("*", min(n-8, 20))
	return prefix + masked + suffix
}

// extractContext returns up to 2 lines of context around lineIdx.
func extractContext(lines []string, lineIdx int) string {
	start := lineIdx - 1
	if start < 0 {
		start = 0
	}
	end := lineIdx + 2
	if end > len(lines) {
		end = len(lines)
	}
	var parts []string
	for _, l := range lines[start:end] {
		if utf8.ValidString(l) {
			parts = append(parts, l)
		}
	}
	return strings.Join(parts, "\n")
}

// truncate shortens a string to maxLen runes, appending "..." if cut.
func truncate(s string, maxLen int) string {
	runes := []rune(s)
	if len(runes) <= maxLen {
		return s
	}
	return string(runes[:maxLen]) + "..."
}

// min returns the smaller of two ints (Go 1.21+ has built-in, keep for compatibility).
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
