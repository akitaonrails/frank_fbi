# CLAUDE.md — Frank FBI (Fraud Bureau of Investigation)

## Project Summary

Frank FBI is a headless Rails 8.1 email fraud/spam detection system. It receives forwarded suspicious emails via Gmail IMAP, analyzes them through a 6-layer pipeline, and replies with a score and explanation report. Also supports a lighter 3-layer messenger triage pipeline for WhatsApp/Telegram/Signal screenshots.

## Tech Stack

- Ruby 4.0.1, Rails 8.1.2 (API-only)
- SQLite3 for all databases (primary, queue, cache, cable)
- Solid Queue for background jobs
- ruby_llm gem for LLM calls via OpenRouter
- ferrum gem for headless Chrome screenshots
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

# Triage a messenger screenshot .eml
bin/rails "frank_fbi:triage_eml[path/to/file.eml,submitter@email.com]"

# Start the background worker
bin/jobs

# Start the IMAP mail fetcher
bin/rails frank_fbi:fetch_mail

# Start the web server
bin/rails server

# Manage allowed senders
bin/rails "frank_fbi:add_sender[user@example.com]"
bin/rails "frank_fbi:add_senders[a@example.com,b@example.com]"
bin/rails "frank_fbi:remove_sender[user@example.com]"
bin/rails frank_fbi:list_senders

# Build and push Docker image to Gitea registry
bin/deploy
```

## Architecture

### Fraud Analysis Pipeline (6 Layers)

1. **Header Auth** (weight 0.15) — SPF/DKIM/DMARC/ARC checks, Reply-To mismatch, antispam headers. Fully deterministic.
2. **Sender Reputation** (weight 0.15) — WHOIS domain age, DNSBL blacklists, local reputation DB. Depends on Layer 1 (sender IP).
3. **Content Analysis** (weight 0.15) — Pattern matching for urgency, financial fraud, PII requests, authority impersonation, URL shorteners, dangerous attachments. Fully deterministic.
4. **External API** (weight 0.15) — VirusTotal and URLhaus URL scanning. Depends on Layer 3 (extracted URLs).
5. **Entity Verification** (weight 0.10) — OSINT-based sender identity verification via Brave Search, domain checks, web presence validation. Depends on Layers 1+3. After completion, triggers ScreenshotCaptureJob to capture website screenshots of reference links.
6. **LLM Analysis** (weight 0.30) — 3 parallel LLM consultations via OpenRouter (Claude, GPT-4o, Grok) with consensus building. Depends on Layers 1-5.

Final score: `sum(layer_score * weight * confidence) / sum(weight * confidence)`

### Messenger Triage Pipeline (3 Layers)

1. **URL Scan** (weight 0.40) — VirusTotal + URLhaus scanning
2. **File Scan** (weight 0.30) — VirusTotal file scanning
3. **LLM Triage** (weight 0.30) — 3 parallel LLM consultations for messenger scam patterns

### Community Threat Intelligence Reporting

After report delivery, `CommunityReportingJob` submits IOCs from high-confidence fraudulent emails (score >= 85, verdict "fraudulent") to community threat intel databases. Best-effort — errors are logged but never block the pipeline. All API keys are optional; missing keys silently skip that provider.

Providers: ThreatFox (abuse.ch), AbuseIPDB, SpamCop. IOCs extracted: URLs, domains, sender IPs, file hashes. Freemail domains, cloud IPs, and confirmed-clean URLs are filtered out.

Audit trail stored in `CommunityReport` (one per email, idempotent).

### Screenshot Capture

After entity verification finds reference links, ScreenshotCaptureJob captures headless Chrome screenshots (via ferrum) in parallel with LLM analysis. The pipeline waits for screenshots to complete before generating the report. Screenshots are resized to 560px, JPEG quality 60, embedded as base64 in the HTML report. Errors are caught gracefully — report renders without screenshots if capture fails.

### Job Flow (Fraud)

`EmailParsingJob` → Layers 1+3 (parallel) → Layers 2+4+5 (after dependencies) → ScreenshotCaptureJob (after Layer 5) → Layer 6 → `ScoreAggregationJob` → `ReportGenerationJob` → `ReportDeliveryJob` → `CommunityReportingJob` (best-effort)

Orchestrated by `Analysis::PipelineOrchestrator` — each job calls `advance(email)` after completion.

### Data Model

- `Email` — central record, has_many analysis_layers/llm_verdicts, has_one analysis_report/community_report. `pipeline_type` field: "fraud_analysis" (default) or "messenger_triage"
- `AnalysisLayer` — one per layer per email (6 for fraud, 3 for triage), unique on [email_id, layer_name]
- `LlmVerdict` — one per LLM provider per email (3 per email), unique on [email_id, provider]
- `KnownDomain` — domain reputation cache (WHOIS, DNSBL, fraud ratio)
- `KnownSender` — sender reputation tracking, belongs_to KnownDomain
- `UrlScanResult` — VirusTotal/URLhaus cache with TTL, unique on [url, source]
- `AnalysisReport` — rendered HTML/text report per email
- `AllowedSender` — whitelisted sender emails (encrypted, managed by admin)
- `CommunityReport` — audit trail for threat intel submissions (one per email, unique)

### Key Directories

```
app/services/analysis/   — 6 analyzers, consensus builder, score aggregator, pipeline orchestrator
app/services/triage/     — 3 triage analyzers, pipeline orchestrator, report renderer
app/services/community_reporting/ — IOC extractor, threat intel clients (ThreatFox, AbuseIPDB, SpamCop), reporter orchestrator
app/services/            — email_parser, mail_fetcher, screenshot_capturer, API clients (virustotal, urlhaus, whois, brave_search), report_renderer
app/jobs/                — 19 job classes (fraud + triage pipelines + community reporting)
app/mailboxes/           — FraudAnalysisMailbox, MessengerTriageMailbox, AdminCommandMailbox, RejectionMailbox
app/mailers/             — AnalysisReportMailer, AdminMailer
app/models/              — 9 models with validations, associations, encryption
lib/tasks/frank_fbi.rake — rake tasks for analysis, triage, smoke testing, mail fetching, sender management
suspects/                — ~30 sample .eml files used for testing
```

## Docker

### Local Development

`docker-compose.yml` — builds from source, bind mounts `./tmp/docker_storage` and `./tmp/docker_emails`. Do NOT mount `db/` as a volume (it shadows migration files from the image).

### Production

`docker-compose.production.yml` — pulls from Gitea registry at `192.168.0.145:3007`, bind mounts to `/home/akitaonrails/frank_fbi/{storage,emails}`, env_file at `/home/akitaonrails/frank_fbi/.env`. No port exposed (internal Docker network only). Compose file goes in `~/docker/frank_fbi.yml`.

`bin/deploy` — builds and pushes image to the Gitea registry.

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
- `BRAVE_SEARCH_API_KEY` — Entity verification OSINT
- `THREATFOX_AUTH_KEY` — (optional) abuse.ch ThreatFox threat intel submission
- `ABUSEIPDB_API_KEY` — (optional) AbuseIPDB IP reporting
- `SPAMCOP_SUBMISSION_ADDRESS` — (optional) SpamCop email forwarding
- `ADMIN_EMAIL` — admin email for system management via email commands

### Access Control

- `ADMIN_EMAIL` env var defines the single admin who can manage the system
- `AllowedSender` whitelist — only pre-approved emails get analyzed
- Admin sends email commands (subject: add/remove/list/stats) to manage senders
- Non-whitelisted senders receive a rejection reply
- Routing: admin → `AdminCommandMailbox`, allowed → `FraudAnalysisMailbox`, triage → `MessengerTriageMailbox`, others → `RejectionMailbox`

## Security Notes

- `submitter_email` on Email model uses deterministic encryption (always encrypted, queryable)
- Email body content is encrypted post-analysis when verdict is "legitimate"
- HTML body sanitized before storage
- No credentials in code — all via ENV
- WebMock blocks all external HTTP in tests
