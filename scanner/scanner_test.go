package scanner

import (
	"strings"
	"testing"
)

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
