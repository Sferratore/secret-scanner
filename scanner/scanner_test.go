package scanner

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

// entry is a shorthand for building a FileEntry for scanContent tests.
func entry(path, body string) FileEntry {
	return FileEntry{Path: path, Content: []byte(body)}
}

func TestScanContent_HappyPath(t *testing.T) {
	seen := make(map[dedupeKey]bool)
	findings := scanContent(context.Background(), entry("config.yaml", "AWS_KEY=AKIAIOSFODNN7EXAMPLE"), seen)

	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.File != "config.yaml" {
		t.Errorf("File = %q, want config.yaml", f.File)
	}
	if f.Line != 1 {
		t.Errorf("Line = %d, want 1", f.Line)
	}
	if f.Type != "aws_access_key_id" {
		t.Errorf("Type = %q, want aws_access_key_id", f.Type)
	}
	want := "AKIA" + strings.Repeat("*", 12) + "MPLE"
	if f.MatchedValue != want {
		t.Errorf("MatchedValue = %q, want %q", f.MatchedValue, want)
	}
}

func TestScanContent_CaptureGroupPreferred(t *testing.T) {
	// AWS secret access key pattern: full match includes the `aws_secret_access_key: `
	// prefix, capture group 1 is just the 40-char value. scanContent must report
	// the group, not the full match.
	value := "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcd" // 40 chars, [A-Za-z0-9/+=]
	line := "aws_secret_access_key: " + value
	seen := make(map[dedupeKey]bool)
	findings := scanContent(context.Background(), entry("secrets.env", line), seen)

	var got *string
	for i := range findings {
		if findings[i].Type == "aws_secret_access_key" {
			got = &findings[i].MatchedValue
			break
		}
	}
	if got == nil {
		t.Fatalf("no aws_secret_access_key finding; got findings = %+v", findings)
	}
	want := "ABCD" + strings.Repeat("*", 20) + "abcd"
	if *got != want {
		t.Fatalf("MatchedValue = %q, want %q (capture group not used?)", *got, want)
	}
}

func TestScanContent_DedupeWithinFile(t *testing.T) {
	body := "AWS_KEY=AKIAIOSFODNN7EXAMPLE\nOTHER=AKIAIOSFODNN7EXAMPLE"
	seen := make(map[dedupeKey]bool)
	findings := scanContent(context.Background(), entry("a.txt", body), seen)

	count := 0
	for _, f := range findings {
		if f.Type == "aws_access_key_id" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("same secret on 2 lines produced %d findings, want 1", count)
	}
}

func TestScanContent_DedupeAcrossFiles(t *testing.T) {
	line := "AWS_KEY=AKIAIOSFODNN7EXAMPLE"
	seen := make(map[dedupeKey]bool)

	f1 := scanContent(context.Background(), entry("a.txt", line), seen)
	f2 := scanContent(context.Background(), entry("b.txt", line), seen)

	if len(f1) != 1 {
		t.Fatalf("first file: got %d findings, want 1", len(f1))
	}
	if len(f2) != 1 {
		t.Fatalf("second file (different path): got %d findings, want 1", len(f2))
	}
}

func TestScanContent_PlaceholderSkipped(t *testing.T) {
	// 40 x's satisfies the aws_secret_access_key capture-group shape but
	// also matches the placeholderPattern (xxx+). Must be filtered out.
	line := "aws_secret_access_key: " + strings.Repeat("x", 40)
	seen := make(map[dedupeKey]bool)
	findings := scanContent(context.Background(), entry("a.txt", line), seen)

	if len(findings) != 0 {
		t.Fatalf("placeholder not filtered: got %+v", findings)
	}
}

func TestScanContent_FalsePositiveFilterSkipped(t *testing.T) {
	// A real AKIA-shaped string embedded in a regexp.MustCompile call —
	// the FP filter should skip the whole line.
	line := `var r = regexp.MustCompile("AKIAIOSFODNN7EXAMPLE")`
	seen := make(map[dedupeKey]bool)
	findings := scanContent(context.Background(), entry("patterns.go", line), seen)

	if len(findings) != 0 {
		t.Fatalf("FP filter did not skip regexp.MustCompile line: got %+v", findings)
	}
}

func TestScanContent_LongLineSkipped(t *testing.T) {
	// Line > maxLineLength (4 KB) is dropped before any regex runs,
	// even if a real secret is buried inside it.
	line := strings.Repeat(" ", maxLineLength+100) + "AKIAIOSFODNN7EXAMPLE"
	seen := make(map[dedupeKey]bool)
	findings := scanContent(context.Background(), entry("huge.js", line), seen)

	if len(findings) != 0 {
		t.Fatalf("long line not skipped: got %+v", findings)
	}
}

func TestScanContent_PerFileCap(t *testing.T) {
	// Generate 60 distinct AKIA-shaped keys. Each has a unique last-4,
	// so none dedupe together. The per-file cap should stop at exactly 50.
	var b strings.Builder
	for i := range 60 {
		fmt.Fprintf(&b, "AKIA%s%02d\n", strings.Repeat("A", 14), i)
	}
	seen := make(map[dedupeKey]bool)
	findings := scanContent(context.Background(), entry("leaks.txt", b.String()), seen)

	if len(findings) != maxFindingsPerFile {
		t.Fatalf("per-file cap: got %d findings, want %d", len(findings), maxFindingsPerFile)
	}
}

func TestScanContent_LineNumbers1Indexed(t *testing.T) {
	// Secret on the 3rd line of the file → Line should be 3, not 2.
	body := "\n\nAWS_KEY=AKIAIOSFODNN7EXAMPLE"
	seen := make(map[dedupeKey]bool)
	findings := scanContent(context.Background(), entry("a.txt", body), seen)

	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].Line != 3 {
		t.Errorf("Line = %d, want 3 (1-indexed)", findings[0].Line)
	}
}

func TestMaskSecret(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"empty", "", ""},
		{"short 3", "abc", "***"},
		{"boundary 8", "12345678", "********"},
		{"just over 9", "abcdefghi", "abcd*fghi"},
		{"aws-key shape 20", "AKIAIOSFODNN7EXAMPLE", "AKIA" + strings.Repeat("*", 12) + "MPLE"},
		{"cap at 20 stars", strings.Repeat("x", 40), "xxxx" + strings.Repeat("*", 20) + "xxxx"},
		{"unicode 9 runes", "日本語日本語日本語", "日本語日*語日本語"},
		{"unicode boundary 8 runes", "日本語日本語日本", "********"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := maskSecret(tc.input)
			if got != tc.want {
				t.Fatalf("maskSecret(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}
