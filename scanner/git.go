package scanner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
)

// errEntryLimit is a sentinel returned from inner ForEach callbacks to stop
// iteration once the entries slice has hit maxEntries. It is never surfaced
// to callers — the outer loop converts it to a clean early return so the
// partial result set is still usable.
var errEntryLimit = errors.New("entry limit reached")

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

// Resource limits. These are the hard ceilings that protect the process
// against hostile or accidentally huge repositories. Tuned jointly: with the
// server-layer semaphore capping concurrent scans, peak /tmp usage is bounded
// at roughly concurrency * maxCloneSize.
const (
	// maxFileSize is the per-file byte ceiling applied during scanning. Files
	// larger than this are skipped entirely (not truncated) to avoid pathological
	// regex runtimes on huge minified bundles or generated assets.
	maxFileSize = 1 * 1024 * 1024 // 1 MB

	// binaryCheckLen is the prefix length inspected by isBinary to decide
	// whether content looks like a binary blob (null bytes present).
	binaryCheckLen = 512

	// maxCloneSize is the hard on-disk ceiling enforced by the watchdog
	// goroutine while cloning. If the temp directory grows past this before the
	// clone completes, the clone context is canceled and the partial tree is
	// removed. Defends against git bomb / huge-repo DoS.
	maxCloneSize = 700 * 1024 * 1024 // 700 MB

	// maxEntries caps the size of the FileEntry slice produced by WalkHistory
	// so that a repo with millions of small files cannot exhaust RAM.
	maxEntries = 10_000

	// cloneDepth restricts the clone to the most recent N commits on the
	// default branch. Combined with SingleBranch+NoTags, this is the single
	// biggest reduction in bytes fetched for typical repositories.
	cloneDepth = 50

	// cloneTimeout is the wall-clock budget for the clone step alone. It is
	// independent from the outer scan timeout so a slow clone cannot steal all
	// the time the scanner would need afterward.
	cloneTimeout = 60 * time.Second

	// diskCheckInterval is how often the watchdog re-measures the temp dir.
	// Short enough to react well before maxCloneSize is wildly overshot,
	// long enough that the walk itself is not a performance drag.
	diskCheckInterval = 2 * time.Second
)

// CloneResult holds the cloned repository and temp dir path.
type CloneResult struct {
	Repo   *git.Repository
	TmpDir string
}

// CloneRepo clones a public GitHub repository into a temporary directory with
// multiple independent safety limits:
//
//  1. Shallow clone (Depth=cloneDepth) — bounds commit history fetched.
//  2. SingleBranch — fetches only the remote HEAD branch, not every ref.
//  3. NoTags — skips tag objects (which can balloon on release-heavy repos).
//  4. cloneCtx with cloneTimeout — wall-clock deadline just for the clone.
//  5. Disk watchdog goroutine — polls the temp dir and cancels the clone if
//     it blows past maxCloneSize, defending against servers that advertise a
//     reasonable size then stream unbounded data.
//
// On any failure path the temp directory is removed so repeated errors do not
// accumulate on disk.
func CloneRepo(ctx context.Context, repoURL string) (*CloneResult, error) {
	// Create an isolated scratch directory. The "secret-scanner-*" prefix
	// makes the source of any leftover directories obvious during debugging.
	tmpDir, err := os.MkdirTemp("", "secret-scanner-*")
	if err != nil {
		return nil, fmt.Errorf("creating temp dir: %w", err)
	}

	// cloneCtx is derived from the caller's context so outer cancellation
	// still propagates, but it adds its own deadline and cancel func — the
	// watchdog uses cancel() to abort the clone when the disk cap is hit.
	cloneCtx, cancel := context.WithTimeout(ctx, cloneTimeout)
	defer cancel()

	// diskExceeded is set by the watchdog when it trips so the error path can
	// distinguish "killed for size" from a generic transport/network error.
	// atomic.Bool is used because it is read from the main goroutine after
	// the watchdog may have written it.
	var diskExceeded atomic.Bool

	// watchdogDone lets the main goroutine wait for the watchdog to exit
	// before returning. Without this we would race on tmpDir removal.
	watchdogDone := make(chan struct{})

	go func() {
		// close on exit so the main goroutine's <-watchdogDone unblocks no
		// matter which branch we leave through.
		defer close(watchdogDone)

		ticker := time.NewTicker(diskCheckInterval)
		defer ticker.Stop()

		for {
			select {
			case <-cloneCtx.Done():
				// Clone finished (success or failure) or deadline tripped.
				// Either way the watchdog has nothing more to do.
				return
			case <-ticker.C:
				// Re-measure tmpDir. Walk errors are tolerated (transient
				// races with git writing files) — we simply retry next tick.
				if size, err := dirSize(tmpDir); err == nil && size > maxCloneSize {
					diskExceeded.Store(true)
					cancel() // aborts git.PlainCloneContext
					return
				}
			}
		}
	}()

	// PlainCloneContext is the context-aware clone. We force-disable anything
	// that could explode the working copy: history depth, branch fan-out,
	// tag objects. Progress output is discarded — callers don't want it and
	// keeping it in memory would be another small leak vector.
	repo, err := git.PlainCloneContext(cloneCtx, tmpDir, false, &git.CloneOptions{
		URL:          repoURL,
		Progress:     io.Discard,
		Depth:        cloneDepth,
		SingleBranch: true,
		Tags:         git.NoTags,
	})

	// Explicitly cancel before waiting so a watchdog that is still mid-tick
	// gets the signal promptly, then block until it has fully exited.
	cancel()
	<-watchdogDone

	if err != nil {
		// Always clean up partial state. Ignore the error — if RemoveAll
		// fails there is nothing actionable to do and the original clone
		// error is the one worth surfacing.
		os.RemoveAll(tmpDir)

		// Prefer the disk-cap message so operators can tell this case apart
		// from network or auth failures in logs.
		if diskExceeded.Load() {
			return nil, fmt.Errorf("clone exceeded disk cap of %d bytes", maxCloneSize)
		}
		return nil, fmt.Errorf("cloning repository: %w", err)
	}

	return &CloneResult{Repo: repo, TmpDir: tmpDir}, nil
}

// dirSize returns the sum of regular-file sizes under path. It is the
// measurement primitive used by the clone watchdog.
//
// WalkDir is preferred over Walk because it avoids a stat() per entry —
// DirEntry is satisfied from the directory read. We still call d.Info() on
// files to obtain size, but directories cost nothing.
//
// Per-entry errors are swallowed (return nil) because the tree is being
// written concurrently by go-git: a file might disappear between the dirent
// read and the Info() call, and that is expected, not fatal. The next tick
// re-walks anyway.
func dirSize(path string) (int64, error) {
	var total int64
	err := filepath.WalkDir(path, func(_ string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		total += info.Size()
		return nil
	})
	return total, err
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

		// Cap reached — no point walking further refs.
		if len(entries) >= maxEntries {
			break
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

			// Stop the whole iteration once we've collected enough entries.
			if len(entries) >= maxEntries {
				return errEntryLimit
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
					// Re-check the cap inside the inner loop — one commit can
					// touch tens of thousands of files on its own.
					if len(entries) >= maxEntries {
						return errEntryLimit
					}
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
					if len(entries) >= maxEntries {
						return errEntryLimit
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
		// Cap was hit inside the inner ForEach — stop walking refs.
		if errors.Is(err, errEntryLimit) {
			break
		}
	}

	// If we already filled the budget from history, skip the HEAD walk
	// rather than overshoot the cap.
	if len(entries) >= maxEntries {
		return entries, commitCount, nil
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

		if len(entries) >= maxEntries {
			return errEntryLimit
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
