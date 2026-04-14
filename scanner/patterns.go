package scanner

import "regexp"

// Pattern describes a single secret detection rule.
type Pattern struct {
	ID          string
	Type        string
	Description string
	Severity    string // critical | high | medium
	Regex       *regexp.Regexp
}

// Patterns is the master list of all detection rules.
var Patterns = []Pattern{
	// ── AWS ───────────────────────────────────────────────────────────────
	{
		ID: "aws_access_key_id", Type: "aws_access_key_id",
		Description: "AWS Access Key ID detected",
		Severity:    "critical",
		Regex:       regexp.MustCompile(`(?i)(?:^|[^A-Z0-9])(AKIA[0-9A-Z]{16})(?:[^A-Z0-9]|$)`),
	},
	{
		ID: "aws_secret_access_key", Type: "aws_secret_access_key",
		Description: "AWS Secret Access Key detected",
		Severity:    "critical",
		Regex:       regexp.MustCompile(`(?i)(?:aws[_\-\s]?secret[_\-\s]?(?:access[_\-\s]?)?key|aws[_\-\s]?secret)["\s]*[=:]["\s]*([A-Za-z0-9/+=]{40})`),
	},

	// ── Google ────────────────────────────────────────────────────────────
	{
		ID: "google_api_key", Type: "google_api_key",
		Description: "Google API Key detected",
		Severity:    "high",
		Regex:       regexp.MustCompile(`(AIza[0-9A-Za-z\-_]{35})`),
	},
	{
		ID: "google_oauth_client_secret", Type: "google_oauth_client_secret",
		Description: "Google OAuth Client Secret detected",
		Severity:    "high",
		Regex:       regexp.MustCompile(`(?i)(?:google[_\-\s]?(?:oauth[_\-\s]?)?client[_\-\s]?secret|GOCSPX-)["\s]*[=:]["\s]*([A-Za-z0-9_\-]{24,})`),
	},
	{
		ID: "google_service_account", Type: "google_service_account",
		Description: "Google Cloud Service Account JSON key detected",
		Severity:    "critical",
		Regex:       regexp.MustCompile(`"type"\s*:\s*"service_account"`),
	},

	// ── GitHub ────────────────────────────────────────────────────────────
	{
		ID: "github_pat", Type: "github_pat",
		Description: "GitHub Personal Access Token detected",
		Severity:    "critical",
		Regex:       regexp.MustCompile(`(gh[pousr]_[A-Za-z0-9_]{36,255})`),
	},
	{
		ID: "github_oauth_token", Type: "github_oauth_token",
		Description: "GitHub OAuth Token detected",
		Severity:    "critical",
		Regex:       regexp.MustCompile(`(?i)github[_\-\s]?(?:oauth[_\-\s]?)?token["\s]*[=:]["\s]*([A-Za-z0-9_\-]{35,40})`),
	},

	// ── GitLab ────────────────────────────────────────────────────────────
	{
		ID: "gitlab_pat", Type: "gitlab_pat",
		Description: "GitLab Personal Access Token detected",
		Severity:    "critical",
		Regex:       regexp.MustCompile(`(glpat-[A-Za-z0-9_\-]{20,})`),
	},

	// ── Stripe ────────────────────────────────────────────────────────────
	{
		ID: "stripe_live_secret", Type: "stripe_live_secret",
		Description: "Stripe Live Secret Key detected",
		Severity:    "critical",
		Regex:       regexp.MustCompile(`(sk_live_[0-9A-Za-z]{24,})`),
	},
	{
		ID: "stripe_publishable_key", Type: "stripe_publishable_key",
		Description: "Stripe Live Publishable Key detected",
		Severity:    "high",
		Regex:       regexp.MustCompile(`(pk_live_[0-9A-Za-z]{24,})`),
	},

	// ── Twilio ────────────────────────────────────────────────────────────
	{
		ID: "twilio_account_sid", Type: "twilio_account_sid",
		Description: "Twilio Account SID detected",
		Severity:    "high",
		Regex:       regexp.MustCompile(`(AC[a-z0-9]{32})`),
	},
	{
		ID: "twilio_auth_token", Type: "twilio_auth_token",
		Description: "Twilio Auth Token detected",
		Severity:    "critical",
		Regex:       regexp.MustCompile(`(?i)twilio[_\-\s]?auth[_\-\s]?token["\s]*[=:]["\s]*([a-z0-9]{32})`),
	},

	// ── SendGrid ──────────────────────────────────────────────────────────
	{
		ID: "sendgrid_api_key", Type: "sendgrid_api_key",
		Description: "SendGrid API Key detected",
		Severity:    "high",
		Regex:       regexp.MustCompile(`(SG\.[A-Za-z0-9_\-]{22,}\.[A-Za-z0-9_\-]{43,})`),
	},

	// ── Mailgun ───────────────────────────────────────────────────────────
	{
		ID: "mailgun_api_key", Type: "mailgun_api_key",
		Description: "Mailgun API Key detected",
		Severity:    "high",
		Regex:       regexp.MustCompile(`(?i)mailgun[_\-\s]?(?:api[_\-\s]?)?key["\s]*[=:]["\s]*([A-Za-z0-9\-]{32,})`),
	},

	// ── Mailchimp ─────────────────────────────────────────────────────────
	{
		ID: "mailchimp_api_key", Type: "mailchimp_api_key",
		Description: "Mailchimp API Key detected",
		Severity:    "high",
		Regex:       regexp.MustCompile(`([a-f0-9]{32}-us[0-9]{1,2})`),
	},

	// ── Slack ─────────────────────────────────────────────────────────────
	{
		ID: "slack_bot_token", Type: "slack_bot_token",
		Description: "Slack Bot Token detected",
		Severity:    "critical",
		Regex:       regexp.MustCompile(`(xoxb-[0-9A-Za-z\-]{10,})`),
	},
	{
		ID: "slack_user_token", Type: "slack_user_token",
		Description: "Slack User Token detected",
		Severity:    "critical",
		Regex:       regexp.MustCompile(`(xoxp-[0-9A-Za-z\-]{10,})`),
	},
	{
		ID: "slack_webhook_url", Type: "slack_webhook_url",
		Description: "Slack Webhook URL detected",
		Severity:    "high",
		Regex:       regexp.MustCompile(`(https://hooks\.slack\.com/services/T[A-Za-z0-9_]{8,}/B[A-Za-z0-9_]{8,}/[A-Za-z0-9_]{24,})`),
	},

	// ── Discord ───────────────────────────────────────────────────────────
	{
		ID: "discord_bot_token", Type: "discord_bot_token",
		Description: "Discord Bot Token detected",
		Severity:    "critical",
		Regex:       regexp.MustCompile(`([MN][A-Za-z0-9]{23,25}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27,})`),
	},
	{
		ID: "discord_webhook_url", Type: "discord_webhook_url",
		Description: "Discord Webhook URL detected",
		Severity:    "high",
		Regex:       regexp.MustCompile(`(https://discord(?:app)?\.com/api/webhooks/[0-9]{17,20}/[A-Za-z0-9_\-]{68,})`),
	},

	// ── Twitter / X ───────────────────────────────────────────────────────
	{
		ID: "twitter_api_key", Type: "twitter_api_key",
		Description: "Twitter/X API Key detected",
		Severity:    "high",
		Regex:       regexp.MustCompile(`(?i)twitter[_\-\s]?(?:api[_\-\s]?)?(?:key|consumer[_\-\s]?key)["\s]*[=:]["\s]*([A-Za-z0-9]{25,})`),
	},
	{
		ID: "twitter_api_secret", Type: "twitter_api_secret",
		Description: "Twitter/X API Secret detected",
		Severity:    "critical",
		Regex:       regexp.MustCompile(`(?i)twitter[_\-\s]?(?:api[_\-\s]?)?(?:secret|consumer[_\-\s]?secret)["\s]*[=:]["\s]*([A-Za-z0-9]{50,})`),
	},

	// ── Facebook ──────────────────────────────────────────────────────────
	{
		ID: "facebook_app_secret", Type: "facebook_app_secret",
		Description: "Facebook App Secret detected",
		Severity:    "critical",
		Regex:       regexp.MustCompile(`(?i)facebook[_\-\s]?app[_\-\s]?secret["\s]*[=:]["\s]*([A-Za-z0-9]{32})`),
	},

	// ── Azure ─────────────────────────────────────────────────────────────
	{
		ID: "azure_storage_key", Type: "azure_storage_key",
		Description: "Azure Storage Account Key detected",
		Severity:    "critical",
		Regex:       regexp.MustCompile(`(?i)(?:AccountKey|StorageKey)[=\s]*([A-Za-z0-9+/]{86}==)`),
	},
	{
		ID: "azure_sas_token", Type: "azure_sas_token",
		Description: "Azure SAS Token detected",
		Severity:    "high",
		Regex:       regexp.MustCompile(`(?i)(?:sv=\d{4}-\d{2}-\d{2}&(?:ss|spr|se|sp|srt|sig)=[^&\s"']+){3,}`),
	},
	{
		ID: "azure_client_secret", Type: "azure_client_secret",
		Description: "Azure Client Secret detected",
		Severity:    "critical",
		Regex:       regexp.MustCompile(`(?i)azure[_\-\s]?client[_\-\s]?secret["\s]*[=:]["\s]*([A-Za-z0-9~._\-]{34,})`),
	},

	// ── Heroku ────────────────────────────────────────────────────────────
	{
		ID: "heroku_api_key", Type: "heroku_api_key",
		Description: "Heroku API Key detected",
		Severity:    "high",
		Regex:       regexp.MustCompile(`(?i)heroku[_\-\s]?(?:api[_\-\s]?)?key["\s]*[=:]["\s]*([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})`),
	},

	// ── Dropbox ───────────────────────────────────────────────────────────
	{
		ID: "dropbox_access_token", Type: "dropbox_access_token",
		Description: "Dropbox Access Token detected",
		Severity:    "high",
		Regex:       regexp.MustCompile(`(sl\.[A-Za-z0-9_\-]{130,})`),
	},

	// ── Shopify ───────────────────────────────────────────────────────────
	{
		ID: "shopify_access_token", Type: "shopify_access_token",
		Description: "Shopify Access Token detected",
		Severity:    "critical",
		Regex:       regexp.MustCompile(`(shpat_[A-Za-z0-9]{32,})`),
	},

	// ── PayPal ────────────────────────────────────────────────────────────
	{
		ID: "paypal_client_secret", Type: "paypal_client_secret",
		Description: "PayPal Client Secret detected",
		Severity:    "critical",
		Regex:       regexp.MustCompile(`(?i)paypal[_\-\s]?(?:client[_\-\s]?)?secret["\s]*[=:]["\s]*([A-Za-z0-9_\-]{20,})`),
	},

	// ── Braintree ─────────────────────────────────────────────────────────
	{
		ID: "braintree_access_token", Type: "braintree_access_token",
		Description: "Braintree Access Token detected",
		Severity:    "critical",
		Regex:       regexp.MustCompile(`(access_token\$production\$[a-z0-9]{16}\$[a-f0-9]{32})`),
	},

	// ── Square ────────────────────────────────────────────────────────────
	{
		ID: "square_access_token", Type: "square_access_token",
		Description: "Square Access Token detected",
		Severity:    "critical",
		Regex:       regexp.MustCompile(`(sq0atp-[A-Za-z0-9_\-]{22,})`),
	},

	// ── Okta ─────────────────────────────────────────────────────────────
	{
		ID: "okta_api_token", Type: "okta_api_token",
		Description: "Okta API Token detected",
		Severity:    "critical",
		Regex:       regexp.MustCompile(`(?i)okta[_\-\s]?(?:api[_\-\s]?)?token["\s]*[=:]["\s]*([A-Za-z0-9_\-]{42,})`),
	},

	// ── HubSpot ───────────────────────────────────────────────────────────
	{
		ID: "hubspot_api_key", Type: "hubspot_api_key",
		Description: "HubSpot API Key detected",
		Severity:    "high",
		Regex:       regexp.MustCompile(`(?i)hubspot[_\-\s]?(?:api[_\-\s]?)?key["\s]*[=:]["\s]*([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})`),
	},

	// ── Datadog ───────────────────────────────────────────────────────────
	{
		ID: "datadog_api_key", Type: "datadog_api_key",
		Description: "Datadog API Key detected",
		Severity:    "high",
		Regex:       regexp.MustCompile(`(?i)datadog[_\-\s]?(?:api[_\-\s]?)?key["\s]*[=:]["\s]*([a-z0-9]{32})`),
	},

	// ── New Relic ─────────────────────────────────────────────────────────
	{
		ID: "new_relic_license_key", Type: "new_relic_license_key",
		Description: "New Relic License Key detected",
		Severity:    "high",
		Regex:       regexp.MustCompile(`(?i)new[_\-\s]?relic[_\-\s]?(?:license[_\-\s]?)?key["\s]*[=:]["\s]*([A-Za-z0-9]{40})`),
	},

	// ── PagerDuty ─────────────────────────────────────────────────────────
	{
		ID: "pagerduty_api_key", Type: "pagerduty_api_key",
		Description: "PagerDuty API Key detected",
		Severity:    "high",
		Regex:       regexp.MustCompile(`(?i)pagerduty[_\-\s]?(?:api[_\-\s]?)?key["\s]*[=:]["\s]*([A-Za-z0-9_\+]{20,})`),
	},

	// ── Cloudflare ────────────────────────────────────────────────────────
	{
		ID: "cloudflare_api_key", Type: "cloudflare_api_key",
		Description: "Cloudflare API Key detected",
		Severity:    "high",
		Regex:       regexp.MustCompile(`(?i)cloudflare[_\-\s]?(?:api[_\-\s]?)?key["\s]*[=:]["\s]*([A-Za-z0-9_]{37,40})`),
	},
	{
		ID: "cloudflare_api_token", Type: "cloudflare_api_token",
		Description: "Cloudflare API Token detected",
		Severity:    "high",
		Regex:       regexp.MustCompile(`(?i)cloudflare[_\-\s]?(?:api[_\-\s]?)?token["\s]*[=:]["\s]*([A-Za-z0-9_\-]{40,})`),
	},

	// ── DigitalOcean ──────────────────────────────────────────────────────
	{
		ID: "digitalocean_pat", Type: "digitalocean_pat",
		Description: "DigitalOcean Personal Access Token detected",
		Severity:    "critical",
		Regex:       regexp.MustCompile(`(dop_v1_[a-z0-9]{64})`),
	},

	// ── Linode ────────────────────────────────────────────────────────────
	{
		ID: "linode_api_key", Type: "linode_api_key",
		Description: "Linode API Key detected",
		Severity:    "high",
		Regex:       regexp.MustCompile(`(?i)linode[_\-\s]?(?:api[_\-\s]?)?(?:key|token)["\s]*[=:]["\s]*([A-Za-z0-9]{64})`),
	},

	// ── Vultr ─────────────────────────────────────────────────────────────
	{
		ID: "vultr_api_key", Type: "vultr_api_key",
		Description: "Vultr API Key detected",
		Severity:    "high",
		Regex:       regexp.MustCompile(`(?i)vultr[_\-\s]?(?:api[_\-\s]?)?key["\s]*[=:]["\s]*([A-Z0-9]{36})`),
	},

	// ── AI / ML ───────────────────────────────────────────────────────────
	{
		ID: "openai_api_key", Type: "openai_api_key",
		Description: "OpenAI API Key detected",
		Severity:    "critical",
		Regex:       regexp.MustCompile(`(sk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}|sk-proj-[A-Za-z0-9_\-]{50,})`),
	},
	{
		ID: "anthropic_api_key", Type: "anthropic_api_key",
		Description: "Anthropic API Key detected",
		Severity:    "critical",
		Regex:       regexp.MustCompile(`(sk-ant-(?:api03-)?[A-Za-z0-9_\-]{90,})`),
	},
	{
		ID: "huggingface_token", Type: "huggingface_token",
		Description: "Hugging Face Token detected",
		Severity:    "high",
		Regex:       regexp.MustCompile(`(hf_[A-Za-z0-9]{34,})`),
	},

	// ── Mapbox ────────────────────────────────────────────────────────────
	{
		ID: "mapbox_access_token", Type: "mapbox_access_token",
		Description: "Mapbox Access Token detected",
		Severity:    "high",
		Regex:       regexp.MustCompile(`(pk\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+)`),
	},

	// ── Algolia ───────────────────────────────────────────────────────────
	{
		ID: "algolia_api_key", Type: "algolia_api_key",
		Description: "Algolia API Key detected",
		Severity:    "high",
		Regex:       regexp.MustCompile(`(?i)algolia[_\-\s]?(?:api[_\-\s]?)?key["\s]*[=:]["\s]*([A-Za-z0-9]{32})`),
	},
	{
		ID: "algolia_app_id", Type: "algolia_app_id",
		Description: "Algolia Application ID detected",
		Severity:    "medium",
		Regex:       regexp.MustCompile(`(?i)algolia[_\-\s]?app(?:lication)?[_\-\s]?id["\s]*[=:]["\s]*([A-Z0-9]{10})`),
	},

	// ── Firebase ──────────────────────────────────────────────────────────
	{
		ID: "firebase_fcm_key", Type: "firebase_fcm_key",
		Description: "Firebase Cloud Messaging Server Key detected",
		Severity:    "high",
		Regex:       regexp.MustCompile(`(AAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140,})`),
	},
	{
		ID: "firebase_db_url", Type: "firebase_db_url",
		Description: "Firebase Database URL with credentials detected",
		Severity:    "high",
		Regex:       regexp.MustCompile(`https://[a-z0-9\-]+\.firebaseio\.com`),
	},

	// ── Package registries ────────────────────────────────────────────────
	{
		ID: "npm_access_token", Type: "npm_access_token",
		Description: "npm Access Token detected",
		Severity:    "high",
		Regex:       regexp.MustCompile(`(npm_[A-Za-z0-9]{36,})`),
	},
	{
		ID: "pypi_api_token", Type: "pypi_api_token",
		Description: "PyPI API Token detected",
		Severity:    "high",
		Regex:       regexp.MustCompile(`(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,})`),
	},
	{
		ID: "dockerhub_access_token", Type: "dockerhub_access_token",
		Description: "Docker Hub Access Token detected",
		Severity:    "high",
		Regex:       regexp.MustCompile(`(?i)docker[_\-\s]?(?:hub[_\-\s]?)?(?:access[_\-\s]?)?token["\s]*[=:]["\s]*([A-Za-z0-9_\-]{72,})`),
	},
	{
		ID: "terraform_cloud_token", Type: "terraform_cloud_token",
		Description: "Terraform Cloud Token detected",
		Severity:    "high",
		Regex:       regexp.MustCompile(`([A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9_\-]{60,})`),
	},

	// ── Private Keys ──────────────────────────────────────────────────────
	{
		ID: "rsa_private_key", Type: "rsa_private_key",
		Description: "RSA Private Key detected",
		Severity:    "critical",
		Regex:       regexp.MustCompile(`-----BEGIN RSA PRIVATE KEY-----`),
	},
	{
		ID: "ec_private_key", Type: "ec_private_key",
		Description: "EC Private Key detected",
		Severity:    "critical",
		Regex:       regexp.MustCompile(`-----BEGIN EC PRIVATE KEY-----`),
	},
	{
		ID: "dsa_private_key", Type: "dsa_private_key",
		Description: "DSA Private Key detected",
		Severity:    "critical",
		Regex:       regexp.MustCompile(`-----BEGIN DSA PRIVATE KEY-----`),
	},
	{
		ID: "openssh_private_key", Type: "openssh_private_key",
		Description: "OpenSSH Private Key detected",
		Severity:    "critical",
		Regex:       regexp.MustCompile(`-----BEGIN OPENSSH PRIVATE KEY-----`),
	},
	{
		ID: "pgp_private_key", Type: "pgp_private_key",
		Description: "PGP Private Key Block detected",
		Severity:    "critical",
		Regex:       regexp.MustCompile(`-----BEGIN PGP PRIVATE KEY BLOCK-----`),
	},
	{
		ID: "pkcs8_private_key", Type: "pkcs8_private_key",
		Description: "PKCS#8 Private Key detected",
		Severity:    "critical",
		Regex:       regexp.MustCompile(`-----BEGIN PRIVATE KEY-----`),
	},
	{
		ID: "encrypted_private_key", Type: "encrypted_private_key",
		Description: "Encrypted Private Key (PEM) detected",
		Severity:    "critical",
		Regex:       regexp.MustCompile(`-----BEGIN ENCRYPTED PRIVATE KEY-----`),
	},

	// ── Hardcoded Passwords ───────────────────────────────────────────────
	{
		ID: "hardcoded_password", Type: "hardcoded_password",
		Description: "Hardcoded password assignment detected",
		Severity:    "high",
		Regex: regexp.MustCompile(
			`(?i)(?:password|passwd|pwd|secret)\s*[=:]\s*["']([^"']{6,})["']`,
		),
	},
	{
		ID: "basic_auth_url", Type: "basic_auth_url",
		Description: "Basic Auth credentials embedded in URL",
		Severity:    "critical",
		Regex:       regexp.MustCompile(`https?://[^:@\s]+:[^@\s]{3,}@[a-zA-Z0-9\-\.]+`),
	},
	{
		ID: "dotenv_secret", Type: "dotenv_secret",
		Description: ".env style secret assignment detected",
		Severity:    "medium",
		Regex: regexp.MustCompile(
			`(?i)^(?:export\s+)?(?:SECRET|TOKEN|API_KEY|ACCESS_KEY|AUTH_KEY|PRIVATE_KEY|SIGNING_KEY)[A-Z_]*\s*=\s*["']?([^"'\s#]{8,})["']?`,
		),
	},

	// ── JWT ───────────────────────────────────────────────────────────────
	{
		ID: "jwt_token", Type: "jwt_token",
		Description: "JWT Token detected",
		Severity:    "medium",
		Regex:       regexp.MustCompile(`(eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)`),
	},

	// ── Connection Strings ────────────────────────────────────────────────
	{
		ID: "postgres_connection_string", Type: "postgres_connection_string",
		Description: "PostgreSQL connection string with credentials detected",
		Severity:    "critical",
		Regex:       regexp.MustCompile(`postgres(?:ql)?://[^:@\s]+:[^@\s]{3,}@[a-zA-Z0-9\-\.\:]+/[a-zA-Z0-9_\-]+`),
	},
	{
		ID: "mysql_connection_string", Type: "mysql_connection_string",
		Description: "MySQL connection string with credentials detected",
		Severity:    "critical",
		Regex:       regexp.MustCompile(`mysql://[^:@\s]+:[^@\s]{3,}@[a-zA-Z0-9\-\.\:]+/[a-zA-Z0-9_\-]+`),
	},
	{
		ID: "mongodb_connection_string", Type: "mongodb_connection_string",
		Description: "MongoDB connection string with credentials detected",
		Severity:    "critical",
		Regex:       regexp.MustCompile(`mongodb(?:\+srv)?://[^:@\s]+:[^@\s]{3,}@[a-zA-Z0-9\-\.\:,]+`),
	},
	{
		ID: "redis_connection_string", Type: "redis_connection_string",
		Description: "Redis connection string with password detected",
		Severity:    "high",
		Regex:       regexp.MustCompile(`redis://:([^@\s]{3,})@[a-zA-Z0-9\-\.\:]+`),
	},
	{
		ID: "amqp_connection_string", Type: "amqp_connection_string",
		Description: "AMQP/RabbitMQ connection string with credentials detected",
		Severity:    "high",
		Regex:       regexp.MustCompile(`amqps?://[^:@\s]+:[^@\s]{3,}@[a-zA-Z0-9\-\.\:]+`),
	},
	{
		ID: "jdbc_connection_string", Type: "jdbc_connection_string",
		Description: "JDBC connection string with credentials detected",
		Severity:    "high",
		Regex:       regexp.MustCompile(`(?i)jdbc:[a-z]+://[a-zA-Z0-9\-\.\:;/=]+(?:password|pwd)=([^;&\s]{3,})`),
	},
	{
		ID: "odbc_connection_string", Type: "odbc_connection_string",
		Description: "ODBC connection string with credentials detected",
		Severity:    "high",
		Regex:       regexp.MustCompile(`(?i)(?:DSN|Driver)=[^;]+;.*?(?:PWD|Password)=([^;]{3,})`),
	},
	{
		ID: "elasticsearch_with_creds", Type: "elasticsearch_with_creds",
		Description: "Elasticsearch URL with credentials detected",
		Severity:    "high",
		Regex:       regexp.MustCompile(`https?://[^:@\s]+:[^@\s]{3,}@[a-zA-Z0-9\-\.]+(?::\d+)?(?:/_|/[a-z])`),
	},
	{
		ID: "generic_connection_string", Type: "generic_connection_string",
		Description: "Generic connection string with embedded credentials detected",
		Severity:    "medium",
		Regex:       regexp.MustCompile(`(?i)(?:connection[_\-\s]?string|conn[_\-\s]?str)["\s]*[=:]["\s]*["'][^"']*(?:password|pwd|user\s*id)[^"']*["']`),
	},
}

// placeholderPattern matches dummy/placeholder values that should be ignored.
var placeholderPattern = regexp.MustCompile(
	`(?i)^(?:xxx+|your[_\-]?(?:password|secret|key|token)|changeme|change_me|placeholder|example|sample|test|dummy|todo|<[^>]+>|\*{3,}|null|none|N/A|undefined|false|true|0{4,})$`,
)

// IsPlaceholder returns true if the matched value looks like a placeholder.
func IsPlaceholder(val string) bool {
	return placeholderPattern.MatchString(val)
}
