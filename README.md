# Frank FBI — Email Fraud Analysis System

A headless Rails 8 application that analyzes suspicious emails through 5 layers of deterministic checks and LLM analysis, then replies with a concise report including scores and explanations.

Forward a suspicious email to a dedicated Gmail account. Frank FBI parses it, runs it through the analysis pipeline, and replies on the same thread with a verdict and breakdown.

## Important: Use a Dedicated Email Account

**Do not use your personal Gmail account.** Frank FBI manages its inbox programmatically — it marks emails as read after processing and may move or delete messages. Using your personal email risks losing important correspondence.

Create a brand new Gmail account exclusively for Frank FBI:

1. Create a new Gmail account (e.g. `frankfraud.analysis@gmail.com`)
2. Enable 2-Factor Authentication on the account
3. Generate an App Password: Google Account > Security > 2-Step Verification > App passwords
4. Put the email and app password in `.env` as `GMAIL_USERNAME` and `GMAIL_PASSWORD`

This account will be the "drop box" — users forward suspicious emails to it, and Frank FBI replies from it.

## How It Works

```
User forwards suspicious email
        ↓
Gmail (IMAP poll every 30s)
        ↓
Action Mailbox routing
  ├─ Admin email     → AdminCommandMailbox (manage senders)
  ├─ Allowed sender  → FraudAnalysisMailbox (run analysis)
  └─ Everyone else   → RejectionMailbox (send rejection notice)
        ↓
Email Parser (extract metadata, URLs, attachments)
        ↓
5-Layer Analysis Pipeline
        ↓
Score Aggregation & Verdict
        ↓
Report Reply (HTML + plaintext, same email thread)
```

### Access Control

Only pre-approved senders can submit emails for analysis. The admin (defined by `ADMIN_EMAIL` in `.env`) manages the whitelist by sending emails to the Frank FBI address with these subjects:

| Subject keyword | Action |
|----------------|--------|
| `add` | Add email addresses from the body to the whitelist |
| `remove` | Deactivate email addresses from the body |
| `list` | Reply with all active allowed senders |
| `stats` | Reply with system statistics (totals, verdicts, average score) |

All routes verify SPF/DKIM authentication to prevent spoofing.

---

## The Analysis Pipeline

Every submitted email goes through 5 analysis layers. Each layer produces a **score** (0–100), a **weight** (how important it is), and a **confidence** (0.0–1.0, how certain the layer is about its findings). Layers with dependencies wait for their prerequisites before running.

### Layer 1 — Header Authentication (weight: 0.20)

Validates email authentication headers. Fully deterministic, no external calls.

**Checks performed:**

| Check | Pass | Fail | Missing |
|-------|------|------|---------|
| SPF (Sender Policy Framework) | 0 pts | +30 pts | +10 pts |
| DKIM (DomainKeys Identified Mail) | 0 pts | +25 pts | +10 pts |
| DMARC (Domain-based Message Auth) | 0 pts | +25 pts | +10 pts |

**Additional signals:**

- **Reply-To mismatch** — Reply-To domain differs from From domain: **+20 pts** (classic phishing tactic)
- **Microsoft SCL** (Spam Confidence Level) >= 5: **+up to 25 pts**
- **X-Spam-Status: Yes**: **+15 pts**
- **Suspicious mailers** (PHPMailer, SendBlaster, MassMail, etc.): **+15 pts** each
- **ARC chain** — recorded for context, not scored

**Confidence** starts at 0.5, +0.15 for each auth method present (SPF, DKIM, DMARC), capped at 1.0.

Also extracts the **sender IP** from Received headers, which Layer 2 uses for blacklist checks.

---

### Layer 2 — Sender Reputation (weight: 0.20)

Assesses domain and sender credibility. Depends on Layer 1 (needs sender IP).

**Checks performed:**

- **Domain age** (via WHOIS lookup):
  - < 30 days: **+30 pts** — newly registered domains are high risk
  - 30–90 days: **+15 pts**
  - 90–365 days: **+5 pts**
  - Older: 0 pts
- **DNS blacklists** — checks sender IP against known spam blacklists:
  - Each hit: **+15 pts** (capped at 40 pts total)
- **Local reputation database** — tracks fraud ratio from past analyses:
  - Domain fraud ratio > 0.7 (with >= 3 samples): **+25 pts**
  - Domain fraud ratio > 0.4: **+10 pts**
  - Sender fraud ratio > 0.8 (with >= 2 emails): **+20 pts**
- **Freemail detection** — flags gmail.com, yahoo.com, outlook.com, etc. (informational, not scored)

**Confidence** starts at 0.4, +0.2 for each available signal (domain age, blacklist results, prior history), capped at 1.0.

Every analyzed email updates the local reputation records (`KnownDomain`, `KnownSender`), creating a feedback loop for future analyses.

---

### Layer 3 — Content Analysis (weight: 0.25)

Pattern-matches the email body and attachments for fraud indicators. Fully deterministic, no external calls. Runs in parallel with Layer 1 (no dependencies).

**Checks performed:**

| Pattern Category | Points per Match | Cap |
|-----------------|-----------------|-----|
| Urgency language ("act now", "expires today", "account suspended", "verify your identity", "within 24 hours") | +8 pts | 30 pts |
| Financial fraud ("wire transfer", "bitcoin", "lottery winner", "guaranteed returns", "ATM card", "unclaimed funds") | +12 pts | 30 pts |
| PII requests ("social security", "credit card number", "password", "date of birth", "send us your ID") | +15 pts | 30 pts |
| Authority impersonation ("FBI", "IRS", "United Nations", "Department of Treasury", "Interpol", "barrister") | +12 pts | 30 pts |
| Phishing phrases ("click here to verify", "account has been compromised", "unusual activity detected", "failure to comply") | +10 pts | 30 pts |

**Additional signals:**

- **URL shorteners** (bit.ly, tinyurl.com, goo.gl, etc.): **+8 pts** per shortened URL
- **URL mismatches** — display text shows one URL, href goes somewhere else: **+15 pts** each (classic phishing)
- **Dangerous attachments** (.exe, .scr, .bat, .vbs, .js, .ps1, etc.): **+25 pts**
- **Double extensions** (e.g. `invoice.pdf.exe`): **+15 pts**
- **ALL CAPS subject** (>10 chars): **+8 pts**
- **Excessive exclamation marks** (3+ or `!!`): **+5 pts**
- **High URL count** (>10 URLs): **+5 pts**

**Confidence** is based on body length: 1.0 if >200 chars, 0.8 if 50–200, 0.5 if <50.

Also extracts all URLs from the email, which Layer 4 uses for scanning.

---

### Layer 4 — External API Checks (weight: 0.15)

Scans extracted URLs against threat intelligence databases. Depends on Layer 3 (needs extracted URLs).

**Services used:**

- **URLhaus** (abuse.ch) — malware URL database
  - Scans up to 10 URLs
  - Each malicious URL: **+20 pts** (capped at 50 pts)
  - Also checks if the sender's domain is in the malware database: **+25 pts** if found
- **VirusTotal** — multi-engine URL scanner
  - Scans up to 4 URLs (rate limited to 4/minute on free tier)
  - Each flagged URL (malicious + suspicious detections): **+15 pts** (capped at 40 pts)

**Caching:** Results are cached in `UrlScanResult` records — 24 hours for VirusTotal, 12 hours for URLhaus. No redundant API calls for recently scanned URLs.

**Confidence** is 1.0 if >5 URLs scanned, 0.8 if >0 URLs scanned, 0.4 otherwise.

---

### Layer 5 — LLM Analysis (weight: 0.20)

Consults 3 AI models in parallel for independent fraud assessments. Depends on all Layers 1–4 (uses their results as context).

**Models consulted:**

| Provider | Model |
|----------|-------|
| Anthropic | Claude Sonnet |
| OpenAI | GPT-4o |
| xAI | Grok 3 Mini |

Each model receives a structured prompt containing:
- Email metadata (from, reply-to, subject, domain, date)
- Email body (truncated to 2000 chars)
- Extracted URLs (up to 15) and attachment info
- Results from all 4 previous layers (scores and explanations)

Each model returns: a score (0–100), verdict, confidence (0–1), reasoning, and key findings.

**Consensus building** (triggers when >= 2 of 3 models respond):

- **Score** = weighted average by confidence: `sum(score * confidence) / sum(confidence)`
- **Verdict** = majority vote; ties broken by severity (fraudulent > suspicious_likely_fraud > suspicious_likely_ok > legitimate)
- **Consensus confidence**:
  - All 3 agree: average confidence + 0.1 (boosted, capped at 1.0)
  - 2 agree: average confidence * 0.9
  - All 3 disagree: average confidence * 0.7

If an LLM fails to return valid JSON, it defaults to score 50 / suspicious_likely_fraud / confidence 0.3.

---

## Final Score & Verdict

After all 5 layers complete, the **Score Aggregator** computes the final result:

```
final_score = sum(layer_score * weight * confidence) / sum(weight * confidence)
```

Each layer's effective influence = weight * confidence. A layer with high weight but low confidence contributes less than a layer with moderate weight but high confidence.

### Verdict Thresholds

| Score Range | Verdict | Report Icon |
|-------------|---------|-------------|
| 0–25 | Legitimate | ✅ |
| 26–50 | Suspicious (Likely OK) | ⚠️ |
| 51–75 | Suspicious (Likely Fraud) | 🚨 |
| 76–100 | Fraudulent | 🛑 |

### Post-Scoring Actions

- **Reputation update** — the sender domain and sender address records are updated with the verdict, building a reputation history for future analyses
- **Privacy protection** — if the verdict is "legitimate", the email body is encrypted in the database (no need to retain plaintext of confirmed safe emails)
- **Report generation** — an HTML and plaintext report is rendered with the score, verdict, per-layer breakdown, key findings, and AI model verdicts
- **Report delivery** — the report is emailed back to the submitter on the same email thread

---

## Example: Anatomy of a Score

A typical spam email claiming to be an ATM card compensation payment might score like this:

| Layer | Score | Weight | Confidence | Contribution |
|-------|-------|--------|------------|-------------|
| Header Auth | 55/100 | 0.20 | 0.80 | SPF fail, Reply-To mismatch |
| Sender Reputation | 45/100 | 0.20 | 0.60 | Domain < 90 days, 1 blacklist hit |
| Content Analysis | 72/100 | 0.25 | 1.00 | Financial fraud patterns, urgency, PII requests, ALL CAPS |
| External API | 0/100 | 0.15 | 0.40 | No URLs flagged |
| LLM Analysis | 65/100 | 0.20 | 0.85 | Consensus: suspicious_likely_fraud |

**Final score:** ~55/100 — **Suspicious (Likely Fraud)**

Layers 1 and 3 are fully deterministic and always run, even without API keys. Layers 2, 4, and 5 require external API keys but degrade gracefully with low confidence when unavailable.

---

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

# Generate a secret key base (paste into .env)
ruby -rsecurerandom -e 'puts SecureRandom.hex(64)'

# Prepare database
bin/rails db:prepare

# Run tests
bin/rails test

# Run smoke test (processes a known spam email)
bin/rails frank_fbi:smoke_test
```

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

### Manage Allowed Senders

```bash
bin/rails "frank_fbi:add_sender[user@example.com]"
bin/rails "frank_fbi:remove_sender[user@example.com]"
bin/rails frank_fbi:list_senders
```

## Testing

```bash
# Run the full test suite
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

```bash
# Configure
cp .env.example .env
# Fill in all values in .env (see above for key generation commands)

# Build and start everything (volumes auto-create, setup runs migrations)
docker compose up --build -d

# Check logs
docker compose logs -f

# Check health
curl http://localhost:3000/up

# Stop
docker compose down

# Stop and delete all data
docker compose down -v
```

This starts 4 services:

| Service | Purpose |
|---------|---------|
| `setup` | One-shot: runs `db:prepare`, then exits |
| `app` | Rails server on port 3000 (healthchecked at `/up`) |
| `worker` | Solid Queue worker (processes analysis jobs) |
| `mail_fetcher` | Polls Gmail IMAP every 30s, relays to Action Mailbox (waits for app healthcheck) |

## Architecture

### Data Model

- **emails** — Central record per analyzed email (parsed metadata, URLs, attachments, raw source, final score/verdict)
- **analysis_layers** — One record per layer per email (5 per email)
- **llm_verdicts** — One record per LLM consultation (3 per email)
- **known_domains** — Domain reputation cache (WHOIS, DNSBL results, fraud ratio)
- **known_senders** — Sender-level reputation tracking
- **url_scan_results** — VirusTotal/URLhaus result cache with TTL
- **analysis_reports** — Rendered report HTML/text and delivery status
- **allowed_senders** — Whitelisted submitter emails (encrypted)

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
  mailboxes/           — FraudAnalysisMailbox, AdminCommandMailbox, RejectionMailbox
  mailers/             — AnalysisReportMailer (thread-aware reply), AdminMailer
  models/              — 8 models
lib/tasks/             — Rake tasks (analyze, smoke test, fetch mail, sender management)
suspects/              — ~30 sample .eml files for testing
```

## Security

- Submitter email is always encrypted (Active Record Encryption, deterministic/queryable)
- Email body content is encrypted after analysis if the verdict is "legitimate"
- All API keys in environment variables only
- HTML body sanitized before storage
- SPF/DKIM verification at ingress — prevents spoofed submissions
- WebMock blocks all external HTTP in tests

## License

Private.
