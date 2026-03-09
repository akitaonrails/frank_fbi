# Frank FBI — Fraud Bureau of Investigation

A headless Rails 8 application that analyzes suspicious emails through 6 layers of deterministic checks and LLM analysis, then replies with a concise report including scores and explanations.

Forward a suspicious email to a dedicated Gmail account. Frank FBI parses it, runs it through the analysis pipeline, and replies on the same thread with a verdict and breakdown.

## Best Way To Forward

If you use Gmail, prefer **Forward as attachment** instead of the normal inline forward.

- **Forward as attachment** preserves the original message as an `.eml` file, including the original headers, auth results, MIME structure, and original attachments.
- **Inline forward** preserves mostly the visible content and a human-readable summary. It often loses the original SMTP evidence needed for reliable SPF, DKIM, DMARC, and `Received` chain analysis.

### Gmail instructions

On desktop Gmail:

1. In the inbox, select the suspicious email
2. Click **More**
3. Choose **Forward as attachment**
4. Send that attached `.eml` to the Frank FBI mailbox

If a user forwards inline, Frank FBI will still analyze the message content, but the report will warn that header/auth evidence is incomplete and recommend resubmitting as an attachment for a higher-fidelity scan.

If the suspicious email contains attachments, the report now highlights risky file types explicitly. Archive files (`.zip`, `.rar`, `.7z`), macro-enabled Office files (`.docm`, `.xlsm`, `.pptm`), disk images (`.iso`, `.img`), shortcuts (`.lnk`, `.url`), and executables are treated as dangerous or highly suspicious and the user is warned not to open them directly.

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
  │                  → MessengerTriageMailbox (if subject contains "triage")
  └─ Everyone else   → RejectionMailbox (send rejection notice)
        ↓
Email Parser (extract metadata, URLs, attachments)
        ↓
6-Layer Analysis Pipeline (fraud) or 3-Layer Triage Pipeline (messenger)
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

## The Fraud Analysis Pipeline

Every submitted email goes through 6 analysis layers. Each layer produces a **score** (0–100), a **weight** (how important it is), and a **confidence** (0.0–1.0, how certain the layer is about its findings). Layers with dependencies wait for their prerequisites before running.

### Layer 1 — Header Authentication (weight: 0.15)

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

### Layer 2 — Sender Reputation (weight: 0.15)

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

### Layer 3 — Content Analysis (weight: 0.15)

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
- **Dangerous attachments** (.exe, .scr, .bat, .vbs, .js, .ps1, `.lnk`, `.url`, etc.): **+25 pts each** (capped)
- **Highly suspicious attachments** (`.zip`, `.rar`, `.7z`, `.iso`, `.img`, `.docm`, `.xlsm`, `.pptm`, `.one`, `.apk`, attached `.html/.svg`): **+10 to +18 pts each** (capped)
- **Double extensions** (e.g. `invoice.pdf.exe`): **+15 pts**
- **ALL CAPS subject** (>10 chars): **+8 pts**
- **Excessive exclamation marks** (3+ or `!!`): **+5 pts**
- **High URL count** (>10 URLs): **+5 pts**

**Confidence** is based on body length: 1.0 if >200 chars, 0.8 if 50–200, 0.5 if <50.

Also extracts all URLs from the email, which Layer 4 uses for scanning.

Risky attachments are also surfaced prominently in the final report with a plain-language warning telling the user not to open them directly on their workstation.

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

### Layer 5 — Entity Verification (weight: 0.10)

OSINT-based verification of the sender's claimed identity. Depends on Layers 1 + 3 (needs sender info and extracted entities).

**Checks performed:**

- Extracts entities (company names, person names, domains) from the email
- Searches the web via Brave Search API for corroborating evidence
- Verifies sender identity against found references
- Checks domain registration details (age, registrar, blacklist status)
- Detects mismatches between claimed and actual identity

**Output includes:**
- Sender/domain verification status
- Entity mismatches found
- Reference links to verified sources (company websites, LinkedIn, etc.)
- Website screenshots of reference links (captured via headless Chrome, inline in report)

**Screenshot capture** runs in parallel with LLM analysis after entity verification completes. Uses ferrum (headless Chromium) with stealth configuration. Screenshots are resized to 560px width, JPEG quality 60, and embedded as base64 thumbnails in the HTML report. The pipeline waits for screenshots before generating the report, with graceful fallback if capture fails.

---

### Layer 6 — LLM Analysis (weight: 0.30)

Consults 3 AI models in parallel for independent fraud assessments. Depends on all Layers 1–5 (uses their results as context).

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
- Results from all 5 previous layers (scores and explanations)

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

## Messenger Triage Pipeline

For WhatsApp/Telegram/Signal message screenshots forwarded via email, a lighter 3-layer triage pipeline is available (triggered when the email subject contains "triage"):

1. **URL Scan** (weight 0.40) — scans extracted URLs via VirusTotal and URLhaus
2. **File Scan** (weight 0.30) — scans attached files via VirusTotal
3. **LLM Triage** (weight 0.30) — 3 parallel LLM consultations focused on messenger scam patterns

---

## Final Score & Verdict

After all layers complete, the **Score Aggregator** computes the final result:

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
- **Community threat intel** (optional, beta) — submits IOCs from high-confidence fraudulent emails to community threat databases. See [Community Reporting](#community-threat-intelligence-reporting-beta) below.

---

## Example: Anatomy of a Score

A typical spam email claiming to be an ATM card compensation payment might score like this:

| Layer | Score | Weight | Confidence | Contribution |
|-------|-------|--------|------------|-------------|
| Header Auth | 55/100 | 0.15 | 0.80 | SPF fail, Reply-To mismatch |
| Sender Reputation | 45/100 | 0.15 | 0.60 | Domain < 90 days, 1 blacklist hit |
| Content Analysis | 72/100 | 0.15 | 1.00 | Financial fraud patterns, urgency, PII requests, ALL CAPS |
| External API | 0/100 | 0.15 | 0.40 | No URLs flagged |
| Entity Verification | 60/100 | 0.10 | 0.50 | Sender not verified, no corroborating web presence |
| LLM Analysis | 65/100 | 0.30 | 0.85 | Consensus: suspicious_likely_fraud |

**Final score:** ~55/100 — **Suspicious (Likely Fraud)**

Layers 1 and 3 are fully deterministic and always run, even without API keys. Layers 2, 4, 5, and 6 require external API keys but degrade gracefully with low confidence when unavailable.

---

## Community Threat Intelligence Reporting (Beta)

After delivering a report, Frank FBI can optionally submit Indicators of Compromise (IOCs) from high-confidence fraudulent emails (score >= 85, verdict "fraudulent") to community threat intelligence databases:

| Provider | What gets reported |
|---|---|
| **ThreatFox** (abuse.ch) | Malicious URLs, domains |
| **AbuseIPDB** | Sender IPs |
| **SpamCop** | Full email forwarding |

**Do NOT enable community reporting until you have tested the system extensively and are confident in the accuracy of its verdicts.** This is a beta feature. False positives submitted to threat intel databases can harm innocent domain owners, get legitimate IPs blacklisted, and erode trust in shared threat feeds. Run Frank FBI for a while with community reporting disabled, review the reports it generates, and only enable it once you trust the pipeline's judgment on your real-world email traffic.

To enable, set the corresponding API keys in `.env`:

```bash
# All optional — missing keys silently skip that provider
THREATFOX_AUTH_KEY=your-key    # abuse.ch ThreatFox
ABUSEIPDB_API_KEY=your-key     # AbuseIPDB
SPAMCOP_SUBMISSION_ADDRESS=    # SpamCop forwarding address
```

With no keys set, community reporting is completely inert — no API calls, no errors.

### Anti-Poisoning Safeguards

The IOC extractor includes hardening against adversarial manipulation:

- **Well-known domain filtering** — ~40 major domains (Microsoft, Apple, Google, Amazon, PayPal, government domains, etc.) are never reported as malicious IOCs, even if an attacker embeds them in a spam email to poison threat databases.
- **Scan-verified clean domains** — domains where all scanned URLs came back clean from VirusTotal/URLhaus are excluded.
- **Infrastructure IP filtering** — email provider MTA IPs (Google, Microsoft Exchange Online, SendGrid, Amazon SES) and cloud provider ranges are never reported to AbuseIPDB, preventing false reports from forged Received headers.
- **Freemail domain filtering** — shared email infrastructure domains (gmail.com, yahoo.com, etc.) are excluded.

Audit trail is stored in `CommunityReport` (one per email, idempotent).

---

## Rate Limiting

Per-sender rate limiting prevents a compromised allowed sender from flooding the system. Controlled by `MAX_SUBMISSIONS_PER_HOUR` (default: 20, set to 0 to disable).

- Rate check happens **after** SPF/DKIM authentication — a spoofed sender does not burn the real sender's quota
- Rate-limited senders receive a specific "rate limit exceeded" notice instead of the generic rejection
- Uses `Rails.cache` with 1-hour expiry — counter resets automatically

```bash
# In .env
MAX_SUBMISSIONS_PER_HOUR=20  # default, 0 = disabled
```

---

## Requirements

- Ruby 4.0.1
- SQLite3
- Docker & Docker Compose (for deployment)
- Chromium (for website screenshots, included in Docker image)

### API Keys (optional but recommended)

- **OpenRouter** — for LLM analysis (Layer 6). Get a key at [openrouter.ai](https://openrouter.ai)
- **VirusTotal** — for URL scanning (Layer 4). Free tier: 4 requests/min. [virustotal.com](https://www.virustotal.com)
- **WhoisXML API** — for WHOIS/domain age (Layer 2). Free tier: 500 lookups/month. [whoisxmlapi.com](https://www.whoisxmlapi.com)
- **Brave Search** — for entity verification OSINT (Layer 5). [brave.com/search/api](https://brave.com/search/api/)

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

### Triage a Messenger Screenshot

```bash
bin/rails "frank_fbi:triage_eml[path/to/message.eml,submitter@email.com]"
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
bin/rails "frank_fbi:add_senders[user1@example.com,user2@example.com]"
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
  services/          — EmailParser, ReportRenderer, ScreenshotCapturer
  services/analysis/ — HeaderAuthAnalyzer, ContentAnalyzer, ScoreAggregator, LlmConsensusBuilder
  integration/       — Full pipeline from .eml file through scoring and report generation
  factories/         — FactoryBot factories for Email, AnalysisLayer, LlmVerdict
```

External API calls are blocked in tests via WebMock. The `suspects/` directory contains ~30 real `.eml` files used as test fixtures.

## Docker Deployment

### Local Development

```bash
# Configure
cp .env.example .env
# Fill in all values in .env

# Build and start (data stored in ./tmp/)
docker compose up --build -d

# Check logs
docker compose logs -f

# Stop
docker compose down
```

### Production (home server)

```bash
# On dev machine: build and push to Gitea registry
bin/deploy

# On server: create data directories
mkdir -p ~/frank_fbi/storage ~/frank_fbi/emails

# Copy .env to server
scp .env server:~/frank_fbi/.env

# Copy compose file
scp docker-compose.production.yml server:~/docker/frank_fbi.yml

# Start
cd ~/docker
docker compose -f frank_fbi.yml pull
docker compose -f frank_fbi.yml up -d
```

This starts 4 services:

| Service | Purpose |
|---------|---------|
| `setup` | One-shot: runs `db:prepare`, then exits |
| `app` | Rails server (internal only, no port exposed) |
| `worker` | Solid Queue worker (processes analysis jobs) |
| `mail_fetcher` | Polls Gmail IMAP every 30s, relays to Action Mailbox (waits for app healthcheck) |

## Architecture

### Data Model

- **emails** — Central record per analyzed email (parsed metadata, URLs, attachments, raw source, final score/verdict)
- **analysis_layers** — One record per layer per email (6 for fraud, 3 for triage)
- **llm_verdicts** — One record per LLM consultation (3 per email)
- **known_domains** — Domain reputation cache (WHOIS, DNSBL results, fraud ratio)
- **known_senders** — Sender-level reputation tracking
- **url_scan_results** — VirusTotal/URLhaus result cache with TTL
- **analysis_reports** — Rendered report HTML/text and delivery status
- **allowed_senders** — Whitelisted submitter emails (encrypted)
- **community_reports** — Audit trail for threat intel submissions (one per email)

### Job Pipeline (Fraud Analysis)

```
EmailParsingJob
  → HeaderAuthAnalysisJob (Layer 1)  ─┐
  → ContentAnalysisJob (Layer 3)     ─┤ parallel
                                      ↓
  → SenderReputationAnalysisJob (Layer 2, needs Layer 1)
  → ExternalApiAnalysisJob (Layer 4, needs Layer 3)
  → EntityVerificationJob (Layer 5, needs Layers 1+3)
    → ScreenshotCaptureJob (after Layer 5, parallel with Layer 6)
                                      ↓
  → LlmAnalysisJob (Layer 6, needs Layers 1-5)
    ├─ LlmConsultationJob (Claude)  ┐
    ├─ LlmConsultationJob (GPT-4o)  ├ parallel
    └─ LlmConsultationJob (Grok)    ┘
                                      ↓
  → ScoreAggregationJob → ReportGenerationJob → ReportDeliveryJob → CommunityReportingJob (best-effort)
```

### Key Directories

```
app/
  services/analysis/   — 6 analyzers, consensus builder, score aggregator, pipeline orchestrator
  services/triage/     — 3 triage analyzers, pipeline orchestrator, report renderer
  services/            — email parser, mail fetcher, API clients, report renderer, screenshot capturer
  jobs/                — 18 job classes (fraud pipeline + triage pipeline)
  mailboxes/           — FraudAnalysisMailbox, MessengerTriageMailbox, AdminCommandMailbox, RejectionMailbox
  mailers/             — AnalysisReportMailer (thread-aware reply), AdminMailer
  models/              — 8 models
lib/tasks/             — Rake tasks (analyze, triage, smoke test, fetch mail, sender management)
suspects/              — ~30 sample .eml files for testing
```

## Security

- Submitter email is always encrypted (Active Record Encryption, deterministic/queryable)
- Email body content is encrypted after analysis if the verdict is "legitimate"
- All API keys in environment variables only
- HTML body sanitized before storage
- SPF/DKIM verification at ingress — prevents spoofed submissions
- Per-sender rate limiting — prevents flooding from compromised accounts
- IOC extraction hardened against domain poisoning and IP forgery attacks
- WebMock blocks all external HTTP in tests

## License

Private.
