# Secret Scanner

A stateless REST API written in Go that scans public GitHub repositories for secrets and sensitive information in source code and recent commit history.

## How it works

1. Accepts a GitHub repository URL via `POST /api/scan`.
2. Validates the URL against a strict allowlist (HTTPS only, `github.com` host only, no credentials, no query/fragment, no path traversal).
3. Shallow-clones the default branch — the 50 most recent commits — into a temporary directory.
4. Walks every cloned commit, diffing against its parent to find added/modified lines, and also scans the full HEAD tree.
5. Runs 70+ regex patterns against every line, skipping binaries, lockfiles, long lines, and placeholder-shaped values.
6. Deduplicates findings, masks secret values, and returns a structured JSON report.
7. Removes the temporary clone automatically on every exit path.

## Tech Stack

| Component | Library |
|-----------|---------|
| Language | Go 1.22 |
| HTTP Framework | [Gin](https://github.com/gin-gonic/gin) |
| Git operations | [go-git](https://github.com/go-git/go-git) |
| UUID generation | [google/uuid](https://github.com/google/uuid) |

## Project Structure

```
secret-scanner/
├── main.go                     — server entry, middleware, rate limiter, CORS, HTTP timeouts
├── main_test.go                — rate-limiter tests
├── config.json                 — runtime configuration (port, CORS, rate limits)
├── go.mod / go.sum
├── api/
│   ├── handler.go              — HTTP handlers, URL sanitization, scan-slot semaphore
│   └── handler_test.go         — URL sanitization, body-size, saturation 503 tests
├── scanner/
│   ├── scanner.go              — scan orchestration, dedupe, masking, per-file caps
│   ├── scanner_test.go         — unit tests for scanContent and maskSecret
│   ├── scanner_full_test.go    — end-to-end integration test over a real git repo
│   ├── patterns.go             — 70+ detection patterns + placeholder filter
│   └── git.go                  — clone watchdog, history walking, file filtering
└── models/
    └── models.go               — request / response structs
```

## Usage Tutorial

### 1. Prerequisites

- Go **1.22** or newer (`go version`)
- Network access to GitHub for cloning
- Up to ~700 MB free space in `$TMPDIR` per concurrent scan (see [Software Specs](#software-specs))

### 2. Install and build

```bash
git clone https://github.com/bl4ckw1ng/secret-scanner
cd secret-scanner
go mod tidy
```

### 3. Configure (optional)

Runtime configuration lives in `config.json` next to the binary and is loaded at startup. All fields are optional; missing fields fall back to the defaults below.

| Field | Default | Effect |
|-------|---------|--------|
| `port` | `"8080"` | HTTP listen port |
| `allowed_origins` | `["*"]` | `Access-Control-Allow-Origin` |
| `allowed_methods` | `["GET", "POST", "OPTIONS"]` | `Access-Control-Allow-Methods` |
| `allowed_headers` | `["Content-Type", "Authorization"]` | `Access-Control-Allow-Headers` |
| `rate_limit` | `5` | Max requests per IP per window |
| `rate_window_secs` | `60` | Rate-limit window length (seconds) |
| `scan_timeout_secs` | `300` | Parsed but not wired in; scan timeout is compiled in at 5 min. See [Software Specs](#software-specs) |
| `max_file_size_mb` | `1` | Parsed but not wired in; per-file ceiling is compiled in at 1 MB |

### 4. Run

```bash
go run main.go
# → "Secret Scanner API listening on :8080"
```

For a release build:

```bash
go build -o secret-scanner .
./secret-scanner
```

### 5. Issue a scan

```bash
curl -X POST http://localhost:8080/api/scan \
  -H "Content-Type: application/json" \
  -d '{"repo_url": "https://github.com/trufflesecurity/test_keys"}'
```

Responses come back as a single JSON object (no streaming). Small repos return in under a second; a maxed-out scan can take up to 5 minutes.

### 6. Interpret the response

Every finding carries the file path, the 1-indexed line, the commit that introduced it, the author, and a **masked** value:

```
AKIA************MPLE          ← first 4 + stars + last 4
```

For triage, sort by `severity` (`critical` → `high` → `medium`) then by `commit_date`.

### 7. Troubleshooting

| You see | It means |
|---------|----------|
| `400 request body must contain repo_url` | Empty or malformed JSON, or body over 1 KB |
| `400 only github.com repositories are supported` | URL did not pass the allowlist — check scheme, host, credentials, query params |
| `404 repository not found or private` | Repo does not exist or requires authentication — private repos are unsupported |
| `408 scan timeout` | Scan exceeded 5 minutes |
| `429 rate limit exceeded, try again later` | Your IP exhausted its quota for the current window |
| `503 scanner busy, please retry shortly` | All concurrent scan slots were occupied for the full 10 s queue wait |
| `500 internal scan error` | Unexpected failure — check server logs |

## API Reference

### `GET /health`

Returns `{"status": "ok"}`. Use for liveness probes.

### `POST /api/scan`

Scan a public GitHub repository.

**Request**
```json
{ "repo_url": "https://github.com/owner/repo" }
```

**Response `200 OK`**
```json
{
  "repo_url": "https://github.com/owner/repo",
  "scanned_at": "2025-04-14T10:00:00Z",
  "stats": {
    "total_commits_scanned": 42,
    "total_files_scanned": 87,
    "total_findings": 5
  },
  "findings": [
    {
      "id": "3f2a1b4c-...",
      "type": "aws_access_key_id",
      "severity": "critical",
      "description": "AWS Access Key ID detected",
      "file": "config/settings.py",
      "line": 42,
      "commit": "a1b2c3d4e5f6...",
      "commit_message": "add config",
      "commit_author": "John Doe",
      "commit_date": "2024-01-15T09:30:00Z",
      "matched_value": "AKIA************MPLE",
      "context": "AWS_ACCESS_KEY_ID = 'AKIA************MPLE'"
    }
  ]
}
```

**Error Responses**

| Status | Meaning |
|--------|---------|
| `400` | Invalid body, oversize body, or invalid GitHub URL |
| `404` | Repository not found or private |
| `408` | Scan timeout |
| `429` | Rate limit exceeded |
| `500` | Internal scan error |
| `503` | All scanner slots busy |

## Software Specs

Every limit below is enforced in code. They are tuned jointly so that peak disk and memory stay bounded under adversarial input (`maxConcurrentScans × maxCloneSize` is the worst case for `/tmp`).

### Process-level

| Setting | Value | Defined in |
|---------|------:|------------|
| Max concurrent scans | 3 | `api/handler.go` |
| Scan queue wait (before 503) | 10 s | `api/handler.go` |
| Listen port | 8080 (configurable) | `config.json` |

### Per-request (HTTP)

| Setting | Value | Defined in |
|---------|------:|------------|
| Max request body | 1 KB | `api/handler.go` |
| Max repo URL length | 256 chars | `api/handler.go` |
| Read header timeout | 10 s | `main.go` |
| Read timeout | 30 s | `main.go` |
| Write timeout | 5 min 30 s | `main.go` |
| Idle timeout | 60 s | `main.go` |
| Rate limit | 5 req / 60 s per IP (configurable) | `config.json` |

### Per-scan

| Setting | Value | Defined in |
|---------|------:|------------|
| Scan timeout (wall clock) | 5 min | `api/handler.go` |
| Max entries (commits × files walked) | 10 000 | `scanner/git.go` |
| Max per-line length | 4 KB | `scanner/scanner.go` |
| Per-file timeout | 3 s | `scanner/scanner.go` |
| Context-cancel check stride | every 256 lines | `scanner/scanner.go` |

### Per-clone

| Setting | Value | Defined in |
|---------|------:|------------|
| Clone depth | 50 commits (shallow) | `scanner/git.go` |
| Clone timeout | 60 s | `scanner/git.go` |
| Max clone size on disk | 700 MB | `scanner/git.go` |
| Disk-usage check interval | 2 s | `scanner/git.go` |
| Single branch only | true | `scanner/git.go` |
| Tags fetched | none | `scanner/git.go` |

### Per-file (scan inclusion)

| Setting | Value | Defined in |
|---------|------:|------------|
| Max file size | 1 MB | `scanner/git.go` |
| Skipped extensions | binary, image, archive, font, media | `scanner/git.go` |
| Skipped filenames | `go.sum`, `package-lock.json`, `yarn.lock`, `Gemfile.lock`, `Pipfile.lock`, `poetry.lock`, `composer.lock`, `pnpm-lock.yaml` | `scanner/git.go` |
| Binary detection | null byte in first 512 bytes | `scanner/git.go` |

### Per-report (output)

| Setting | Value | Defined in |
|---------|------:|------------|
| Max findings per file | 50 | `scanner/scanner.go` |
| Max total findings | 1 000 | `scanner/scanner.go` |
| Masking format | `<first 4>****<last 4>`, up to 20 stars | `scanner/scanner.go` |

## Detected Secret Types

### API Keys
| Type | Severity |
|------|----------|
| AWS Access Key ID | critical |
| AWS Secret Access Key | critical |
| Google API Key | high |
| Google OAuth Client Secret | high |
| Google Cloud Service Account JSON | critical |
| GitHub Personal Access Token (ghp_, gho_, ghu_, ghs_, ghr_) | critical |
| GitHub OAuth Token | critical |
| GitLab Personal Access Token (glpat-) | critical |
| Stripe Live Secret Key (sk_live_) | critical |
| Stripe Live Publishable Key (pk_live_) | high |
| Twilio Account SID | high |
| Twilio Auth Token | critical |
| SendGrid API Key (SG.) | high |
| Mailgun API Key | high |
| Mailchimp API Key | high |
| Slack Bot Token (xoxb-) | critical |
| Slack User Token (xoxp-) | critical |
| Slack Webhook URL | high |
| Discord Bot Token | critical |
| Discord Webhook URL | high |
| Twitter/X API Key | high |
| Twitter/X API Secret | critical |
| Facebook App Secret | critical |
| Azure Storage Account Key | critical |
| Azure SAS Token | high |
| Azure Client Secret | critical |
| Heroku API Key | high |
| Dropbox Access Token | high |
| Shopify Access Token | critical |
| PayPal Client Secret | critical |
| Braintree Access Token | critical |
| Square Access Token | critical |
| Okta API Token | critical |
| HubSpot API Key | high |
| Datadog API Key | high |
| New Relic License Key | high |
| PagerDuty API Key | high |
| Cloudflare API Key | high |
| Cloudflare API Token | high |
| DigitalOcean Personal Access Token | critical |
| Linode API Key | high |
| Vultr API Key | high |
| OpenAI API Key | critical |
| Anthropic API Key | critical |
| Hugging Face Token (hf_) | high |
| Mapbox Access Token (pk.eyJ) | high |
| Algolia API Key | high |
| Algolia Application ID | medium |
| Firebase Cloud Messaging Key | high |
| Firebase Database URL | high |
| npm Access Token | high |
| PyPI API Token | high |
| Docker Hub Access Token | high |
| Terraform Cloud Token | high |

### Private Keys & Certificates
| Type | Severity |
|------|----------|
| RSA Private Key | critical |
| EC Private Key | critical |
| DSA Private Key | critical |
| OpenSSH Private Key | critical |
| PGP Private Key Block | critical |
| PKCS#8 Private Key | critical |
| Encrypted Private Key (PEM) | critical |

### Hardcoded Credentials
| Type | Severity |
|------|----------|
| Hardcoded password assignment | high |
| Basic Auth in URLs | critical |
| .env style secret assignment | medium |

### Tokens & Connection Strings
| Type | Severity |
|------|----------|
| JWT Token | medium |
| PostgreSQL connection string | critical |
| MySQL connection string | critical |
| MongoDB connection string | critical |
| Redis connection string with password | high |
| AMQP/RabbitMQ connection string | high |
| JDBC connection string with credentials | high |
| ODBC connection string with credentials | high |
| Elasticsearch URL with credentials | high |
| Generic connection string with credentials | medium |

## Security Notes

- **Secret values are always masked**: only the first 4 and last 4 characters are shown; the middle is replaced with `*`.
- Actual secret values are **never logged or stored**.
- Only public repositories can be scanned: no authentication path exists.
- URL input is allowlisted through 11 validation rules before any clone is attempted (scheme, host, credentials, query, fragment, traversal, ASCII, length, null byte, final regex shape).
- Request body is capped at 1 KB and rejected before JSON parsing if exceeded.
- Per-IP rate limiting plus a global concurrency semaphore bound the blast radius of hostile callers.
- A background watchdog aborts any clone that exceeds the on-disk size cap mid-transfer.

## Limitations

- Private repositories are not supported.
- Only the **most recent 50 commits of the default branch** are scanned (shallow, single-branch clone). Secrets committed and then rewritten before this window are not visible.
- Pattern-based detection can produce false positives in test/example code; a small false-positive filter covers common cases (`regexp.MustCompile`, `example.com`, `test.*key`, and similar markers).
- No persistent storage — each request is stateless and starts from a fresh clone.

## Testing

```bash
go test ./...            # unit + integration tests across all packages
go test ./... -race      # same, with the race detector
go test ./... -count=1   # bypass the test cache
```

The suite includes:

- **URL sanitization**: 21 accept/reject cases (SSRF, protocol smuggling, host confusion, path traversal, unicode, null byte)
- **Secret masking**: boundary cases, cap at 20 stars, unicode rune counting
- **Core scan logic**: patterns, capture-group selection, dedupe (within/across files), placeholder filter, false-positive filter, per-file cap, long-line skip, 1-indexed line numbers
- **Request body size limit**: including a 1 MB fast-reject timing check
- **Per-IP rate limiter**: under limit, over limit, IP isolation, window rollover
- **Concurrency semaphore**: 503 behaviour when all slots are held
- **Full end-to-end run**: real go-git clone from a freshly seeded local repository, exercising the complete pipeline
