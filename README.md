# Secret Scanner

A stateless REST API written in Go that scans public GitHub repositories for secrets and sensitive information — including the **full commit history**.

## How it works

1. Accepts a GitHub repository URL via `POST /api/scan`
2. Clones the repository (full depth) into a temporary directory
3. Walks **all commits across all branches** and diffs each commit against its parent
4. Also scans the current HEAD file tree
5. Runs 70+ regex patterns against every added/modified line
6. Deduplicates findings, masks secret values, and returns a structured JSON report
7. Cleans up the temp directory automatically

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
├── main.go               — Server entry point, middleware, routes
├── go.mod / go.sum
├── api/
│   └── handler.go        — HTTP handlers (scan + health)
├── scanner/
│   ├── scanner.go        — Core scanning logic, dedup, masking
│   ├── patterns.go       — All 70+ regex patterns
│   └── git.go            — Git clone, history walking, file filtering
└── models/
    └── models.go         — Request/response structs
```

## Running Locally

### Prerequisites

- Go 1.22+

### Steps

```bash
git clone https://github.com/bl4ckw1ng/secret-scanner
cd secret-scanner
go mod tidy
go run main.go
```

The server starts on port **8080**.

## API Reference

### `GET /health`

Returns `{"status": "ok"}`. Use for liveness probes.

---

### `POST /api/scan`

Scan a public GitHub repository for secrets.

**Request**
```json
{
  "repo_url": "https://github.com/owner/repo"
}
```

**Response `200 OK`**
```json
{
  "repo_url": "https://github.com/owner/repo",
  "scanned_at": "2025-04-14T10:00:00Z",
  "stats": {
    "total_commits_scanned": 142,
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

| Status | Body |
|--------|------|
| `400` | `{"error": "invalid GitHub URL"}` |
| `404` | `{"error": "repository not found or private"}` |
| `408` | `{"error": "scan timeout"}` |
| `500` | `{"error": "internal scan error"}` |

### Example with curl

```bash
curl -X POST http://localhost:8080/api/scan \
  -H "Content-Type: application/json" \
  -d '{"repo_url": "https://github.com/trufflesecurity/test_keys"}'
```

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

- **Secret values are always masked**: only the first 4 and last 4 characters are shown; the rest is replaced with `*`
- Actual secret values are **never logged or stored**
- Only public repositories can be scanned (no authentication support)
- Scan timeout is **5 minutes** per repository
- Binary files, files over 1 MB, and lock files are automatically skipped

## Limitations

- Private repositories are not supported
- Very large repositories may hit the 5-minute timeout
- Pattern-based detection may produce false positives for test/example code
