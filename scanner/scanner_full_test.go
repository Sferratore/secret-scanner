package scanner

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
)

// seedRepo initializes a non-bare git repo in dir, writes each fixture file,
// stages and commits them as a single commit, and returns the author sig.
// Any failure fails the test directly — this is setup, not the subject.
func seedRepo(t *testing.T, dir string, fixtures map[string]string) *object.Signature {
	t.Helper()

	repo, err := git.PlainInit(dir, false)
	if err != nil {
		t.Fatalf("PlainInit: %v", err)
	}
	wt, err := repo.Worktree()
	if err != nil {
		t.Fatalf("Worktree: %v", err)
	}

	for name, content := range fixtures {
		full := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", name, err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		if _, err := wt.Add(name); err != nil {
			t.Fatalf("add %s: %v", name, err)
		}
	}

	sig := &object.Signature{
		Name:  "Test User",
		Email: "test@example.com",
		When:  time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
	}
	if _, err := wt.Commit("seed fixtures", &git.CommitOptions{Author: sig}); err != nil {
		t.Fatalf("commit: %v", err)
	}
	return sig
}

// TestScan_FullRun drives the entire scanner pipeline against a real
// filesystem-backed git repository: CloneRepo (go-git), WalkHistory, per-entry
// scanContent, dedupe, and stats aggregation. Nothing is mocked.
func TestScan_FullRun(t *testing.T) {
	srcDir := t.TempDir()

	awsRaw := "AKIAIOSFODNN7EXAMPLE"
	awsLine := "AWS_KEY=" + awsRaw
	ghRaw := "ghp_aAbBcCdDeEfFgGhHiIjJkKlLmMnNoOpPqQrR"
	ghLine := "export GH_TOKEN=" + ghRaw

	sig := seedRepo(t, srcDir, map[string]string{
		"config.yaml":   awsLine + "\n",
		"deploy.sh":     ghLine + "\n",
		"docs.md":       `api_key = "your_secret"` + "\n", // placeholder-filtered
		"image.png":     awsRaw,                            // skipped by extension
		"sub/clean.txt": "nothing sensitive here\n",
	})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// go-git's PlainCloneContext accepts a local filesystem path as the URL.
	result, err := Scan(ctx, srcDir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	if result.TotalCommitsScanned < 1 {
		t.Errorf("TotalCommitsScanned = %d, want >= 1", result.TotalCommitsScanned)
	}
	if result.TotalFilesScanned < 3 {
		t.Errorf("TotalFilesScanned = %d, want >= 3 (config.yaml, deploy.sh, docs.md, sub/clean.txt)", result.TotalFilesScanned)
	}

	byFile := map[string][]string{}
	for _, f := range result.Findings {
		byFile[f.File] = append(byFile[f.File], f.Type)
	}

	if !slices.Contains(byFile["config.yaml"], "aws_access_key_id") {
		t.Errorf("config.yaml: got %v, want aws_access_key_id; all findings=%+v", byFile["config.yaml"], result.Findings)
	}
	if !slices.Contains(byFile["deploy.sh"], "github_pat") {
		t.Errorf("deploy.sh: got %v, want github_pat; all findings=%+v", byFile["deploy.sh"], result.Findings)
	}

	// Binary extension must be skipped even though it contains an AKIA-shape string.
	if got := byFile["image.png"]; len(got) != 0 {
		t.Errorf("image.png produced findings = %v, want none (extension skip)", got)
	}

	// Secret-leak invariant: no raw secret value, masking marker present.
	for _, f := range result.Findings {
		if strings.Contains(f.MatchedValue, awsRaw) {
			t.Errorf("raw AWS key leaked in MatchedValue: %+v", f)
		}
		if strings.Contains(f.MatchedValue, ghRaw) {
			t.Errorf("raw GH PAT leaked in MatchedValue: %+v", f)
		}
		if !strings.Contains(f.MatchedValue, "*") {
			t.Errorf("MatchedValue = %q should contain '*' (masking marker)", f.MatchedValue)
		}
		if strings.Contains(f.MatchedValue, "your_secret") {
			t.Errorf("placeholder leaked in MatchedValue: %+v", f)
		}
	}

	// Commit metadata must be populated end-to-end.
	for _, f := range result.Findings {
		if f.Commit == "" {
			t.Errorf("Commit empty on finding %+v", f)
		}
		if f.CommitAuthor != sig.Name {
			t.Errorf("CommitAuthor = %q, want %q", f.CommitAuthor, sig.Name)
		}
	}
}

