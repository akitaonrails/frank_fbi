# CLAUDE.md — Frank FBI

## Project Summary

Frank FBI is a headless Rails 8.1 email fraud/spam detection system. It receives forwarded suspicious emails via Gmail IMAP, analyzes them through a 5-layer pipeline, and replies with a score and explanation report.

## Tech Stack

- Ruby 4.0.1, Rails 8.1.2 (API-only)
- SQLite3 for all databases (primary, queue, cache, cable)
- Solid Queue for background jobs
- ruby_llm gem for LLM calls via OpenRouter
- Action Mailbox for inbound email processing
- Docker Compose for deployment (4 services)

## Commands

```bash
# Run tests
bin/rails test

# Run smoke test (known spam .eml through deterministic layers)
bin/rails frank_fbi:smoke_test

# Analyze a specific .eml file
bin/rails "frank_fbi:analyze_eml[path/to/file.eml,submitter@email.com]"

# Start the background worker
bin/jobs

# Start the IMAP mail fetcher
bin/rails frank_fbi:fetch_mail

# Start the web server
bin/rails server

# Manage allowed senders
bin/rails "frank_fbi:add_sender[user@example.com]"
bin/rails "frank_fbi:remove_sender[user@example.com]"
bin/rails frank_fbi:list_senders
```

## Architecture

### Analysis Pipeline (5 Layers)

1. **Header Auth** (weight 0.20) — SPF/DKIM/DMARC/ARC checks, Reply-To mismatch, antispam headers. Fully deterministic.
2. **Sender Reputation** (weight 0.20) — WHOIS domain age, DNSBL blacklists, local reputation DB. Depends on Layer 1 (sender IP).
3. **Content Analysis** (weight 0.25) — Pattern matching for urgency, financial fraud, PII requests, authority impersonation, URL shorteners, dangerous attachments. Fully deterministic.
4. **External API** (weight 0.15) — VirusTotal and URLhaus URL scanning. Depends on Layer 3 (extracted URLs).
5. **LLM Analysis** (weight 0.20) — 3 parallel LLM consultations via OpenRouter (Claude, GPT-4o, Grok) with consensus building. Depends on Layers 1-4.

Final score: `sum(layer_score * weight * confidence) / sum(weight * confidence)`

### Job Flow

`EmailParsingJob` → Layers 1+3 (parallel) → Layers 2+4 (after dependencies) → Layer 5 → `ScoreAggregationJob` → `ReportGenerationJob` → `ReportDeliveryJob`

Orchestrated by `Analysis::PipelineOrchestrator` — each job calls `advance(email)` after completion.

### Data Model

- `Email` — central record, has_many analysis_layers/llm_verdicts, has_one analysis_report
- `AnalysisLayer` — one per layer per email (5 per email), unique on [email_id, layer_name]
- `LlmVerdict` — one per LLM provider per email (3 per email), unique on [email_id, provider]
- `KnownDomain` — domain reputation cache (WHOIS, DNSBL, fraud ratio)
- `KnownSender` — sender reputation tracking, belongs_to KnownDomain
- `UrlScanResult` — VirusTotal/URLhaus cache with TTL, unique on [url, source]
- `AnalysisReport` — rendered HTML/text report per email
- `AllowedSender` — whitelisted sender emails (encrypted, managed by admin)

### Key Directories

```
app/services/analysis/   — analyzers, consensus builder, score aggregator, pipeline orchestrator
app/services/            — email_parser, mail_fetcher, API clients (virustotal, urlhaus, whois), report_renderer
app/jobs/                — 10 job classes for pipeline stages
app/mailboxes/           — FraudAnalysisMailbox, AdminCommandMailbox, RejectionMailbox
app/mailers/             — AnalysisReportMailer, AdminMailer
app/models/              — 8 models with validations, associations, encryption
lib/tasks/frank_fbi.rake — rake tasks for analysis, smoke testing, mail fetching, sender management
suspects/                — ~30 sample .eml files used for testing
```

## Conventions

- All services return the layer/result object they create/update
- Analyzers follow the pattern: `initialize(email)`, `analyze` method that creates/updates an AnalysisLayer
- Jobs call the analyzer then `PipelineOrchestrator.advance(email)` to trigger next stages
- External API clients check `UrlScanResult` cache before making network calls
- Tests use FactoryBot for model creation, WebMock to block external calls
- Test against real .eml files from `suspects/` via `create_email_from_eml(filename)` helper

## Environment Variables

All secrets in `.env` (see `.env.example`):
- `ACTIVE_RECORD_ENCRYPTION_*` — 3 keys for Active Record Encryption
- `GMAIL_USERNAME` / `GMAIL_PASSWORD` — Gmail IMAP/SMTP credentials
- `RAILS_INBOUND_EMAIL_PASSWORD` — Action Mailbox relay auth
- `OPENROUTER_API_KEY` — LLM access via OpenRouter
- `VIRUSTOTAL_API_KEY` — URL scanning
- `WHOISXML_API_KEY` — WHOIS lookups
- `ADMIN_EMAIL` — admin email for system management via email commands

### Access Control

- `ADMIN_EMAIL` env var defines the single admin who can manage the system
- `AllowedSender` whitelist — only pre-approved emails get analyzed
- Admin sends email commands (subject: add/remove/list/stats) to manage senders
- Non-whitelisted senders receive a rejection reply
- Routing: admin → `AdminCommandMailbox`, allowed → `FraudAnalysisMailbox`, others → `RejectionMailbox`

## Security Notes

- `submitter_email` on Email model uses deterministic encryption (always encrypted, queryable)
- Email body content is encrypted post-analysis when verdict is "legitimate"
- HTML body sanitized before storage
- No credentials in code — all via ENV
- WebMock blocks all external HTTP in tests
