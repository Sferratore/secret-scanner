package scanner

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
)

// skipExtensions lists file extensions that never contain secrets.
var skipExtensions = map[string]bool{
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true,
	".svg": true, ".ico": true, ".pdf": true, ".zip": true,
	".tar": true, ".gz": true, ".bz2": true, ".xz": true,
	".exe": true, ".dll": true, ".so": true, ".dylib": true,
	".woff": true, ".woff2": true, ".ttf": true, ".eot": true,
	".mp4": true, ".mp3": true, ".avi": true, ".mov": true,
	".bin": true, ".dat": true, ".class": true, ".pyc": true,
}

// skipFiles lists specific filenames that are never useful to scan.
var skipFiles = map[string]bool{
	"go.sum":              true,
	"package-lock.json":   true,
	"yarn.lock":           true,
	"Gemfile.lock":        true,
	"Pipfile.lock":        true,
	"poetry.lock":         true,
	"composer.lock":       true,
	"pnpm-lock.yaml":      true,
}

const (
	maxFileSize    = 1 * 1024 * 1024 // 1 MB
	binaryCheckLen = 512
)

// CloneResult holds the cloned repository and temp dir path.
type CloneResult struct {
	Repo   *git.Repository
	TmpDir string
}

// CloneRepo clones a public GitHub repository into a temporary directory.
func CloneRepo(ctx context.Context, repoURL string) (*CloneResult, error) {
	tmpDir, err := os.MkdirTemp("", "secret-scanner-*")
	if err != nil {
		return nil, fmt.Errorf("creating temp dir: %w", err)
	}

	repo, err := git.PlainCloneContext(ctx, tmpDir, false, &git.CloneOptions{
		URL:      repoURL,
		Progress: io.Discard,
		Depth:    0, // full history
	})
	if err != nil {
		os.RemoveAll(tmpDir)
		return nil, fmt.Errorf("cloning repository: %w", err)
	}

	return &CloneResult{Repo: repo, TmpDir: tmpDir}, nil
}

// FileEntry represents a file at a particular point in history.
type FileEntry struct {
	Path          string
	Content       []byte
	CommitHash    string
	CommitMessage string
	CommitAuthor  string
	CommitDate    interface{} // time.Time stored here
	FromHistory   bool       // true = from commit diff, false = HEAD tree
}

// WalkHistory iterates all commits across all branches and yields file entries
// for added/modified lines. It also yields all files from the HEAD tree.
func WalkHistory(ctx context.Context, result *CloneResult) ([]FileEntry, int, error) {
	repo := result.Repo
	var entries []FileEntry
	seenCommits := make(map[plumbing.Hash]bool)
	commitCount := 0

	// Collect all references (branches, tags, etc.)
	refs, err := repo.References()
	if err != nil {
		return nil, 0, fmt.Errorf("listing references: %w", err)
	}

	var refList []plumbing.Hash
	refs.ForEach(func(ref *plumbing.Reference) error {
		if ref.Type() == plumbing.HashReference {
			refList = append(refList, ref.Hash())
		}
		return nil
	})

	// Walk commit history for each ref
	for _, refHash := range refList {
		select {
		case <-ctx.Done():
			return entries, commitCount, fmt.Errorf("scan timeout exceeded")
		default:
		}

		logOpts := &git.LogOptions{From: refHash, Order: git.LogOrderCommitterTime}
		commitIter, err := repo.Log(logOpts)
		if err != nil {
			continue
		}

		err = commitIter.ForEach(func(c *object.Commit) error {
			select {
			case <-ctx.Done():
				return fmt.Errorf("timeout")
			default:
			}

			if seenCommits[c.Hash] {
				return nil
			}
			seenCommits[c.Hash] = true
			commitCount++

			// Get diff against first parent
			var parentTree *object.Tree
			if c.NumParents() > 0 {
				parent, err := c.Parent(0)
				if err == nil {
					parentTree, _ = parent.Tree()
				}
			}

			currentTree, err := c.Tree()
			if err != nil {
				return nil
			}

			changes, err := currentTree.Diff(parentTree)
			if err != nil {
				// If diff fails, fall back to scanning all files in commit
				changes = nil
			}

			if changes != nil {
				for _, change := range changes {
					// Skip deletes
					if change.To.Name == "" {
						continue
					}
					if shouldSkipFile(change.To.Name) {
						continue
					}

					blob, err := repo.BlobObject(change.To.TreeEntry.Hash)
					if err != nil {
						continue
					}
					if blob.Size > maxFileSize {
						continue
					}

					content, err := readBlob(blob)
					if err != nil || isBinary(content) {
						continue
					}

					entries = append(entries, FileEntry{
						Path:          change.To.Name,
						Content:       content,
						CommitHash:    c.Hash.String(),
						CommitMessage: strings.TrimSpace(c.Message),
						CommitAuthor:  c.Author.Name,
						CommitDate:    c.Author.When,
						FromHistory:   true,
					})
				}
			} else if parentTree == nil {
				// Initial commit — scan all files
				currentTree.Files().ForEach(func(f *object.File) error {
					if shouldSkipFile(f.Name) {
						return nil
					}
					if f.Size > maxFileSize {
						return nil
					}
					content, err := readFile(f)
					if err != nil || isBinary(content) {
						return nil
					}
					entries = append(entries, FileEntry{
						Path:          f.Name,
						Content:       content,
						CommitHash:    c.Hash.String(),
						CommitMessage: strings.TrimSpace(c.Message),
						CommitAuthor:  c.Author.Name,
						CommitDate:    c.Author.When,
						FromHistory:   true,
					})
					return nil
				})
			}

			return nil
		})
		commitIter.Close()
		if err != nil && strings.Contains(err.Error(), "timeout") {
			return entries, commitCount, fmt.Errorf("scan timeout exceeded")
		}
	}

	// Walk HEAD file tree (current state)
	head, err := repo.Head()
	if err != nil {
		return entries, commitCount, nil
	}

	headCommit, err := repo.CommitObject(head.Hash())
	if err != nil {
		return entries, commitCount, nil
	}

	headTree, err := headCommit.Tree()
	if err != nil {
		return entries, commitCount, nil
	}

	headTree.Files().ForEach(func(f *object.File) error {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timeout")
		default:
		}

		if shouldSkipFile(f.Name) {
			return nil
		}
		if f.Size > maxFileSize {
			return nil
		}
		content, err := readFile(f)
		if err != nil || isBinary(content) {
			return nil
		}
		entries = append(entries, FileEntry{
			Path:          f.Name,
			Content:       content,
			CommitHash:    headCommit.Hash.String(),
			CommitMessage: strings.TrimSpace(headCommit.Message),
			CommitAuthor:  headCommit.Author.Name,
			CommitDate:    headCommit.Author.When,
			FromHistory:   false,
		})
		return nil
	})

	return entries, commitCount, nil
}

// shouldSkipFile returns true for files we should not scan.
func shouldSkipFile(name string) bool {
	base := filepath.Base(name)
	if skipFiles[base] {
		return true
	}
	ext := strings.ToLower(filepath.Ext(name))
	return skipExtensions[ext]
}

// isBinary returns true if the content appears to be binary (null bytes in first 512 bytes).
func isBinary(data []byte) bool {
	check := data
	if len(check) > binaryCheckLen {
		check = check[:binaryCheckLen]
	}
	return bytes.IndexByte(check, 0) >= 0
}

// readBlob reads a git blob object into bytes.
func readBlob(blob *object.Blob) ([]byte, error) {
	r, err := blob.Reader()
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(r)
}

// readFile reads a git file object into bytes.
func readFile(f *object.File) ([]byte, error) {
	r, err := f.Reader()
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(r)
}
