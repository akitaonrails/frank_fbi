# Frank FBI — Email Fraud Analysis System

A headless Rails 8 application that analyzes suspicious emails through 5 layers of deterministic checks and LLM analysis, then replies with a concise report including scores and explanations.

Forward a suspicious email to a dedicated Gmail account. Frank FBI parses it, runs it through the analysis pipeline, and replies on the same thread with a verdict and breakdown.

## How It Works

```
Gmail (IMAP poll) → Action Mailbox → Email Parser → Analysis Pipeline → Report Reply
```

### Analysis Layers

| # | Layer | Weight | Method |
|---|-------|--------|--------|
| 1 | Header Authentication | 0.20 | SPF, DKIM, DMARC, ARC, Reply-To mismatch, antispam headers |
| 2 | Sender Reputation | 0.20 | WHOIS domain age, DNSBL checks, local reputation database |
| 3 | Content Analysis | 0.25 | Urgency language, financial fraud, PII requests, authority impersonation, URL shorteners, dangerous attachments |
| 4 | External API Checks | 0.15 | VirusTotal URL scanning, URLhaus malware database |
| 5 | LLM Analysis | 0.20 | 3 parallel consultations (Claude, GPT-4o, Grok) via OpenRouter with consensus building |

### Final Score

```
final_score = sum(layer_score * weight * confidence) / sum(weight * confidence)
```

| Score Range | Verdict |
|-------------|---------|
| 0-25 | Legitimate |
| 26-50 | Suspicious (likely OK) |
| 51-75 | Suspicious (likely fraud) |
| 76-100 | Fraudulent |

### Security

- Submitter email is always encrypted (Active Record Encryption, deterministic/queryable)
- Email body content is encrypted after analysis if the verdict is "legitimate" (protect real people's privacy)
- All API keys in environment variables only
- HTML body sanitized before storage

## Requirements

- Ruby 4.0.1
- SQLite3
- Docker & Docker Compose (for deployment)

### API Keys (optional but recommended)

- **OpenRouter** — for LLM analysis (Layer 5). Get a key at [openrouter.ai](https://openrouter.ai)
- **VirusTotal** — for URL scanning (Layer 4). Free tier: 4 requests/min. [virustotal.com](https://www.virustotal.com)
- **WhoisXML API** — for WHOIS/domain age (Layer 2). Free tier: 500 lookups/month. [whoisxmlapi.com](https://www.whoisxmlapi.com)

Layers 1 and 3 are fully deterministic and require no API keys.

## Setup

### Local Development

```bash
# Clone and install
bundle install

# Copy env and fill in your keys
cp .env.example .env
# Edit .env with your API keys and encryption keys

# Generate encryption keys (paste into .env)
bin/rails db:encryption:init

# Prepare database
bin/rails db:prepare

# Run tests
bin/rails test

# Run smoke test (processes a known spam email)
bin/rails frank_fbi:smoke_test
```

### Gmail Setup

1. Create a Gmail account (or use an existing one) dedicated to receiving forwarded emails
2. Enable 2-Factor Authentication on the account
3. Generate an App Password: Google Account > Security > 2-Step Verification > App passwords
4. Put the email and app password in `.env` as `GMAIL_USERNAME` and `GMAIL_PASSWORD`

## Running

### Analyze a Single Email File

```bash
bin/rails "frank_fbi:analyze_eml[suspects/YOUR ATM CARD COMPENSATION PAYMENT !!!!.eml]"
```

### Analyze All Sample Emails

```bash
bin/rails frank_fbi:analyze_suspects
```

### Start the Worker (processes jobs)

```bash
bin/jobs
```

### Start the Mail Fetcher (polls Gmail)

```bash
bin/rails frank_fbi:fetch_mail
```

### Start the Web Server

```bash
bin/rails server
```

## Testing

```bash
# Run the full test suite (59 tests)
bin/rails test

# Run a specific test file
bin/rails test test/services/analysis/content_analyzer_test.rb

# Run the smoke test (parses a known spam .eml, runs deterministic layers, verifies score)
bin/rails frank_fbi:smoke_test
```

### Test Structure

```
test/
  models/            — Email, AnalysisLayer, KnownDomain validations and associations
  services/          — EmailParser, ReportRenderer
  services/analysis/ — HeaderAuthAnalyzer, ContentAnalyzer, ScoreAggregator, LlmConsensusBuilder
  integration/       — Full pipeline from .eml file through scoring and report generation
  factories/         — FactoryBot factories for Email, AnalysisLayer, LlmVerdict
```

External API calls are blocked in tests via WebMock. The `suspects/` directory contains ~30 real `.eml` files used as test fixtures.

## Docker Deployment

### Create External Volumes

```bash
docker volume create frank_fbi_db
docker volume create frank_fbi_storage
docker volume create frank_fbi_emails
```

### Configure

```bash
cp .env.example .env
# Fill in all values in .env
```

### Start

```bash
docker compose up -d
```

This starts 4 services:

| Service | Purpose |
|---------|---------|
| `setup` | One-shot: runs `db:prepare`, then exits |
| `app` | Rails server on port 3000 |
| `worker` | Solid Queue worker (processes analysis jobs) |
| `mail_fetcher` | Polls Gmail IMAP every 30 seconds, relays to Action Mailbox |

### Verify

```bash
# Check logs
docker compose logs -f

# Check health
curl http://localhost:3000/up
```

## Architecture

### Data Model (7 tables)

- **emails** — Central record per analyzed email (parsed metadata, URLs, attachments, raw source, final score/verdict)
- **analysis_layers** — One record per layer per email (5 per email)
- **llm_verdicts** — One record per LLM consultation (3 per email)
- **known_domains** — Domain reputation cache (WHOIS, DNSBL results, fraud ratio)
- **known_senders** — Sender-level reputation tracking
- **url_scan_results** — VirusTotal/URLhaus result cache with TTL
- **analysis_reports** — Rendered report HTML/text and delivery status

### Job Pipeline

```
EmailParsingJob
  → HeaderAuthAnalysisJob (Layer 1)  ─┐
  → ContentAnalysisJob (Layer 3)     ─┤ parallel
                                      ↓
  → SenderReputationAnalysisJob (Layer 2, needs Layer 1 for IP)
  → ExternalApiAnalysisJob (Layer 4, needs Layer 3 for URLs)
                                      ↓
  → LlmAnalysisJob (Layer 5, needs Layers 1-4)
    ├─ LlmConsultationJob (Claude)  ┐
    ├─ LlmConsultationJob (GPT-4o)  ├ parallel
    └─ LlmConsultationJob (Grok)    ┘
                                      ↓
  → ScoreAggregationJob → ReportGenerationJob → ReportDeliveryJob
```

### Key Directories

```
app/
  services/analysis/   — 5 analyzers, consensus builder, score aggregator, pipeline orchestrator
  services/            — email parser, mail fetcher, API clients, report renderer
  jobs/                — 10 job classes
  mailboxes/           — FraudAnalysisMailbox (Action Mailbox)
  mailers/             — AnalysisReportMailer (thread-aware reply)
  models/              — 7 models
lib/tasks/             — Rake tasks (analyze, smoke test, fetch mail)
suspects/              — ~30 sample .eml files for testing
```

## License

Private.
