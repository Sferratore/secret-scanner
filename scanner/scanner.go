package scanner

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/bl4ckw1ng/secret-scanner/models"
	"github.com/google/uuid"
)

// maxLineLength is the per-line byte ceiling applied during scanning. Lines
// longer than this are skipped entirely. This defends against catastrophic
// regex backtracking on minified bundles, base64 blobs, and log dumps —
// inputs where no legitimate secret would live anyway. 4 KB is well above
// any realistic config line that would carry a token.
const maxLineLength = 4 * 1024

// Output-side caps. Independent from the input/work caps (maxEntries,
// maxLineLength) — a single file can still match many patterns, and many
// files can each match a few. These bound the report size so memory and
// response payload stay sane even on dump-style repositories.
const (
	// maxFindingsPerFile caps how many findings one FileEntry can contribute.
	// A single leaked secrets file shouldn't dominate the whole report.
	maxFindingsPerFile = 50

	// maxTotalFindings is the scan-wide ceiling. Once reached, remaining
	// entries are skipped — partial results are still returned to the caller.
	// Far above any volume a human reviewer would triage manually.
	maxTotalFindings = 1000
)

// perFileTimeout is the wall-clock budget for scanning a single FileEntry.
// Backstops regex pathologies that maxLineLength doesn't catch (e.g. many
// medium-length lines all triggering backtracking) and prevents one file
// from monopolising the parent scan budget.
const perFileTimeout = 3 * time.Second

// ctxCheckStride is how often (in lines) the per-file scan loop polls its
// context. Power-of-two so the bitmask check is cheap. Tuned so the select
// cost is invisible on small files but gives sub-second cancel response on
// large ones.
const ctxCheckStride = 256

// falsePositivePattern matches lines that are clearly code defining patterns,
// not actual secrets (e.g. regexp definitions, test fixtures, comments).
var falsePositivePattern = regexp.MustCompile(
	`(?i)regexp\.MustCompile|regexp\.Compile|re\.compile|Pattern\s*=|PATTERN\s*=|` +
		`//\s*|#\s*example|#\s*sample|test.*key|fake.*key|dummy.*key|` +
		`example\.com|sample\.com|foo\.com|localhost`,
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
// It orchestrates the full pipeline: clone -> history walk -> per-file pattern scan -> dedupe.
// The ctx is honored between entries so long scans can be cancelled or time out cleanly.
func Scan(ctx context.Context, repoURL string) (*ScanResult, error) {
	// Clone into a temporary directory; CloneRepo returns the path and metadata.
	cloneResult, err := CloneRepo(ctx, repoURL)
	if err != nil {
		return nil, err
	}
	// Always remove the temp clone when we're done, even on error paths below.
	defer os.RemoveAll(cloneResult.TmpDir)

	// WalkHistory flattens the repo into a list of FileEntry values, one per
	// (commit, file) pair plus the HEAD tree, along with the total commit count.
	entries, commitCount, err := WalkHistory(ctx, cloneResult)
	if err != nil {
		return nil, err
	}

	// seen dedupes findings across the whole scan so the same secret isn't
	// reported once per commit that carried it forward.
	seen := make(map[dedupeKey]bool)
	var findings []models.Finding
	// filesSeen tracks unique file paths touched, used for TotalFilesScanned stats.
	filesSeen := make(map[string]bool)

	for _, entry := range entries {
		// Check cancellation between entries so we don't keep scanning after timeout.
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("scan timeout exceeded")
		default:
		}

		filesSeen[entry.Path] = true
		// Delegate the actual regex matching to scanContent; it mutates `seen`
		// so duplicates found in later entries are skipped. ctx is passed
		// through so per-file deadlines and parent cancellation both bite
		// mid-file rather than waiting for the next entry boundary.
		entryFindings := scanContent(ctx, entry, seen)
		findings = append(findings, entryFindings...)

		// Scan-wide findings ceiling — stop processing further entries once
		// the report is already as full as we're willing to ship. Partial
		// results are still returned.
		if len(findings) >= maxTotalFindings {
			break
		}
	}

	return &ScanResult{
		Findings:            findings,
		TotalCommitsScanned: commitCount,
		TotalFilesScanned:   len(filesSeen),
	}, nil
}

// scanContent runs all patterns against a single FileEntry.
// It scans line-by-line so we can report accurate line numbers and per-line context.
// The seen map is shared with the caller so dedupe spans the entire scan, not just this file.
// ctx carries the parent scan's deadline; a per-file sub-context layered on top
// caps the work this single entry is allowed to do.
func scanContent(ctx context.Context, entry FileEntry, seen map[dedupeKey]bool) []models.Finding {
	// Per-file deadline — bounds any single entry independently from the
	// parent scan timeout, so one bad file can't starve the rest of the repo.
	fileCtx, cancel := context.WithTimeout(ctx, perFileTimeout)
	defer cancel()

	// Split once up-front; reused for matching and for extractContext below.
	lines := strings.Split(string(entry.Content), "\n")
	var findings []models.Finding

	// CommitDate is typed as any on FileEntry; fall back to zero time if absent.
	commitDate, _ := entry.CommitDate.(time.Time)

linesLoop:
	for lineIdx, line := range lines {
		// Periodic cancel/deadline check. Stride keeps the select off the
		// hot path for small files while still aborting large ones promptly.
		if lineIdx%ctxCheckStride == 0 {
			select {
			case <-fileCtx.Done():
				break linesLoop
			default:
			}
		}
		// Skip pathologically long lines before any regex runs. Avoids
		// catastrophic backtracking on minified/blob content.
		if len(line) > maxLineLength {
			continue
		}
		// Try every known pattern on each line. Patterns come from the package-level registry.
		for _, pattern := range Patterns {
			// Use indices (not strings) so we can recover the original slice bounds
			// and decide between the full match and capture group 1.
			matches := pattern.Regex.FindAllStringSubmatchIndex(line, -1)
			for _, match := range matches {
				// Default to the full match span (group 0).
				start, end := match[0], match[1]
				// If the pattern defines a capture group, prefer it — that's where
				// the secret value lives (the surrounding text is just the anchor).
				if len(match) >= 4 && match[2] >= 0 {
					start, end = match[2], match[3]
				}

				raw := line[start:end]
				if len(raw) == 0 {
					continue
				}

				// Skip values that look like placeholders (e.g. "xxx", "<your-key-here>").
				if IsPlaceholder(raw) {
					continue
				}

				// Skip lines that are clearly regex/code definitions, not real secrets.
				// This filters out pattern registries, tests, and examples.
				if falsePositivePattern.MatchString(line) {
					continue
				}

				// Mask before dedupe so the key itself never holds raw secret material.
				masked := maskSecret(raw)
				// Dedupe is per (pattern, masked value, file) — the same secret at
				// the same path across many commits collapses to one finding.
				key := dedupeKey{patternID: pattern.ID, masked: masked, file: entry.Path}
				if seen[key] {
					continue
				}
				seen[key] = true

				// Grab surrounding lines for reviewer context in the report.
				contextStr := extractContext(lines, lineIdx)

				findings = append(findings, models.Finding{
					ID:            uuid.New().String(),
					Type:          pattern.Type,
					Severity:      pattern.Severity,
					Description:   pattern.Description,
					File:          entry.Path,
					Line:          lineIdx + 1, // report 1-indexed lines to match editors
					Commit:        entry.CommitHash,
					CommitMessage: truncate(entry.CommitMessage, 120),
					CommitAuthor:  entry.CommitAuthor,
					CommitDate:    commitDate,
					MatchedValue:  masked,
					Context:       contextStr,
				})

				// Per-file cap: stop scanning this entry once it has produced
				// enough findings on its own. The labeled break exits all
				// three nested loops at once.
				if len(findings) >= maxFindingsPerFile {
					break linesLoop
				}
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
