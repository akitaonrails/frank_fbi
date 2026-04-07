namespace :frank_fbi do
  desc "Backfill encryption for Email#body_html / body_text on rows stored before PR #5"
  task encrypt_email_bodies: :environment do
    total = Email.count
    done = 0
    skipped = 0
    Email.find_each do |email|
      begin
        # Re-assigning the current value forces Active Record Encryption to
        # write the ciphertext back. No-op if already encrypted.
        email.update_columns(
          body_html: email.body_html,
          body_text: email.body_text
        )
        done += 1
      rescue => e
        skipped += 1
        warn "[encrypt_email_bodies] skipped Email##{email.id}: #{e.class}: #{e.message}"
      end
      print "\r  #{done + skipped}/#{total}" if (done + skipped) % 25 == 0
    end
    puts "\nBackfill complete: #{done} updated, #{skipped} skipped"
  end

  desc "Start the IMAP mail fetcher polling loop"
  task fetch_mail: :environment do
    MailFetcher.new.run
  end

  desc "Fetch mail once (single check)"
  task fetch_mail_once: :environment do
    MailFetcher.new.fetch_once
  end

  desc "Process a local .eml file for analysis"
  task :analyze_eml, [:file_path, :submitter_email] => :environment do |_t, args|
    file_path = args[:file_path]
    submitter = args[:submitter_email] || "test@example.com"

    abort("File not found: #{file_path}") unless File.exist?(file_path)

    raw_source = File.read(file_path)
    parser = EmailParser.new(raw_source)
    parsed = parser.parse

    email = Email.create!(
      message_id: parsed[:message_id] || SecureRandom.uuid,
      submitter_email: submitter,
      subject: parsed[:subject],
      from_address: parsed[:from_address],
      from_name: parsed[:from_name],
      reply_to_address: parsed[:reply_to_address],
      sender_domain: parsed[:sender_domain],
      body_text: parsed[:body_text],
      body_html: parsed[:body_html],
      raw_headers: parsed[:raw_headers],
      raw_source: raw_source,
      extracted_urls: parsed[:extracted_urls],
      extracted_emails: parsed[:extracted_emails],
      attachments_info: parsed[:attachments_info],
      received_at: parsed[:received_at],
      status: "analyzing"
    )

    puts "Created Email ##{email.id}: #{email.subject}"
    puts "Starting analysis pipeline..."

    Analysis::PipelineOrchestrator.new(email).start_from_beginning
    puts "Analysis jobs enqueued. Run the worker to process."
  end

  desc "Analyze all .eml files in the suspects directory"
  task analyze_suspects: :environment do
    Dir.glob(Rails.root.join("suspects/*.eml")).each do |file|
      puts "\nAnalyzing: #{File.basename(file)}"
      Rake::Task["frank_fbi:analyze_eml"].invoke(file, "test@example.com")
      Rake::Task["frank_fbi:analyze_eml"].reenable
    end
  end

  desc "Add an allowed sender"
  task :add_sender, [:email] => :environment do |_t, args|
    email = args[:email]
    abort("Usage: bin/rails frank_fbi:add_sender[email@example.com]") unless email.present?

    sender = AllowedSender.find_or_initialize_by(email_address: email.downcase.strip)
    if sender.new_record?
      sender.added_by = "rake"
      sender.save!
      puts "Added: #{email}"
    elsif !sender.active?
      sender.update!(active: true)
      puts "Reactivated: #{email}"
    else
      puts "Already exists: #{email}"
    end
  end

  desc "Remove an allowed sender"
  task :remove_sender, [:email] => :environment do |_t, args|
    email = args[:email]
    abort("Usage: bin/rails frank_fbi:remove_sender[email@example.com]") unless email.present?

    sender = AllowedSender.find_by(email_address: email.downcase.strip)
    if sender&.active?
      sender.update!(active: false)
      puts "Removed: #{email}"
    else
      puts "Not found or already inactive: #{email}"
    end
  end

  desc "Add multiple allowed senders (comma-separated)"
  task :add_senders, [:emails] => :environment do |_t, args|
    emails = args[:emails].to_s.split(",").map(&:strip).reject(&:blank?)
    abort("Usage: bin/rails \"frank_fbi:add_senders[a@example.com,b@example.com]\"") if emails.empty?

    emails.each do |email|
      sender = AllowedSender.find_or_initialize_by(email_address: email.downcase)
      if sender.new_record?
        sender.added_by = "rake"
        sender.save!
        puts "Added: #{email}"
      elsif !sender.active?
        sender.update!(active: true)
        puts "Reactivated: #{email}"
      else
        puts "Already exists: #{email}"
      end
    end
  end

  desc "List all allowed senders"
  task list_senders: :environment do
    senders = AllowedSender.active.order(:email_address)
    if senders.empty?
      puts "No allowed senders configured."
    else
      puts "Allowed senders (#{senders.size}):"
      senders.each { |s| puts "  - #{s.email_address} (added by #{s.added_by || 'unknown'})" }
    end
  end

  desc "Process a local .eml file through the messenger triage pipeline"
  task :triage_eml, [:file_path, :submitter_email] => :environment do |_t, args|
    file_path = args[:file_path]
    submitter = args[:submitter_email] || "test@example.com"

    abort("File not found: #{file_path}") unless File.exist?(file_path)

    raw_source = File.read(file_path)
    parser = EmailParser.new(raw_source)
    parsed = parser.parse

    email = Email.create!(
      message_id: parsed[:message_id] || SecureRandom.uuid,
      submitter_email: submitter,
      pipeline_type: "messenger_triage",
      subject: parsed[:subject],
      from_address: parsed[:from_address],
      from_name: parsed[:from_name],
      reply_to_address: parsed[:reply_to_address],
      sender_domain: parsed[:sender_domain],
      body_text: parsed[:body_text],
      body_html: parsed[:body_html],
      raw_headers: parsed[:raw_headers],
      raw_source: raw_source,
      extracted_urls: parsed[:extracted_urls],
      extracted_emails: parsed[:extracted_emails],
      attachments_info: parsed[:attachments_info],
      received_at: parsed[:received_at],
      status: "analyzing"
    )

    puts "Created Email ##{email.id}: #{email.subject} (messenger_triage)"
    puts "Starting triage pipeline..."

    Triage::PipelineOrchestrator.new(email).start_from_beginning
    puts "Triage jobs enqueued. Run the worker to process."
  end

  desc "Smoke test: process a known spam email and verify high score"
  task smoke_test: :environment do
    spam_file = Rails.root.join("suspects/YOUR ATM CARD COMPENSATION PAYMENT !!!!.eml")
    abort("Smoke test file not found") unless File.exist?(spam_file)

    raw_source = File.read(spam_file)
    parser = EmailParser.new(raw_source)
    parsed = parser.parse

    email = Email.create!(
      message_id: "smoke-test-#{SecureRandom.uuid}",
      submitter_email: "smoke-test@example.com",
      subject: parsed[:subject],
      from_address: parsed[:from_address],
      from_name: parsed[:from_name],
      reply_to_address: parsed[:reply_to_address],
      sender_domain: parsed[:sender_domain],
      body_text: parsed[:body_text],
      body_html: parsed[:body_html],
      raw_headers: parsed[:raw_headers],
      raw_source: raw_source,
      extracted_urls: parsed[:extracted_urls],
      extracted_emails: parsed[:extracted_emails],
      attachments_info: parsed[:attachments_info],
      received_at: parsed[:received_at],
      status: "analyzing"
    )

    # Run deterministic layers synchronously
    Analysis::HeaderAuthAnalyzer.new(email).analyze
    Analysis::ContentAnalyzer.new(email).analyze

    # Run sender reputation (with stubbed external calls in test)
    begin
      Analysis::SenderReputationAnalyzer.new(email).analyze
    rescue => e
      puts "  Sender reputation skipped (external): #{e.message}"
      email.analysis_layers.find_or_create_by!(layer_name: "sender_reputation") do |l|
        l.score = 50
        l.weight = AnalysisLayer.default_weight("sender_reputation")
        l.confidence = 0.3
        l.explanation = "Skipped in smoke test"
        l.status = "completed"
      end
    end

    # Skip external API, entity verification, and LLM for smoke test — create stub layers
    email.analysis_layers.find_or_create_by!(layer_name: "external_api") do |l|
      l.score = 0
      l.weight = AnalysisLayer.default_weight("external_api")
      l.confidence = 0.3
      l.explanation = "Skipped in smoke test"
      l.status = "completed"
    end

    email.analysis_layers.find_or_create_by!(layer_name: "entity_verification") do |l|
      l.score = 60
      l.weight = AnalysisLayer.default_weight("entity_verification")
      l.confidence = 0.4
      l.explanation = "Stubbed entity verification for smoke test"
      l.status = "completed"
    end

    email.analysis_layers.find_or_create_by!(layer_name: "llm_analysis") do |l|
      l.score = 85
      l.weight = AnalysisLayer.default_weight("llm_analysis")
      l.confidence = 0.5
      l.details = {
        content_patterns: {
          urgency: 2, financial_fraud: 3, pii_request: 2,
          authority_impersonation: 2, phishing: 1
        }
      }
      l.explanation = "Stubbed LLM layer for smoke test"
      l.status = "completed"
    end

    # Aggregate
    result = Analysis::ScoreAggregator.new(email).aggregate

    puts "\n=== SMOKE TEST RESULTS ==="
    puts "Subject: #{email.subject}"
    puts "Score: #{result[:score]}/100"
    puts "Verdict: #{result[:verdict]}"
    puts ""

    email.analysis_layers.order(:layer_name).each do |layer|
      puts "  #{layer.layer_name}: #{layer.score}/100 (conf: #{layer.confidence})"
    end

    if result[:score] >= 50
      puts "\n✓ SMOKE TEST PASSED (score #{result[:score]} >= 50)"
    else
      puts "\n✗ SMOKE TEST FAILED (score #{result[:score]} < 50)"
      exit 1
    end
  end

  desc "End-to-end manual test: parse → all layers → LLMs → aggregation → email report (synchronous)"
  task :e2e_test, [:submitter_email, :file_path] => :environment do |_t, args|
    require "json"

    submitter = args[:submitter_email]
    file_path = args[:file_path]

    abort("Usage: bin/rails \"frank_fbi:e2e_test[recipient@example.com,path/to/file.eml]\"") unless submitter.present? && file_path.present?

    eml_path = Pathname.new(file_path)
    eml_path = Rails.root.join(eml_path) unless eml_path.absolute?
    abort("File not found or unreadable: #{eml_path}") unless eml_path.file? && eml_path.readable?

    puts "EML: #{eml_path}"

    raw = File.read(eml_path)
    parser = EmailParser.new(raw)
    parsed = parser.parse

    puts "From: #{parsed[:from_address]} | Domain: #{parsed[:sender_domain]}"
    puts "URLs: #{parsed[:extracted_urls]}"
    puts "Attachments: #{parsed[:attachments_info]}"

    slug = eml_path.basename(".eml").to_s.parameterize.presence || "e2e"
    email = Email.create!(
      message_id: "#{slug}-#{SecureRandom.uuid}",
      submitter_email: submitter,
      subject: parsed[:subject],
      from_address: parsed[:from_address],
      from_name: parsed[:from_name],
      reply_to_address: parsed[:reply_to_address],
      sender_domain: parsed[:sender_domain],
      body_text: parsed[:body_text],
      body_html: parsed[:body_html],
      raw_headers: parsed[:raw_headers],
      raw_source: raw,
      extracted_urls: parsed[:extracted_urls],
      extracted_emails: parsed[:extracted_emails],
      attachments_info: parsed[:attachments_info],
      received_at: parsed[:received_at],
      status: "analyzing"
    )

    puts "Email ##{email.id}"

    # Run deterministic and external layers synchronously
    puts "\n--- Running analysis layers ---"
    Analysis::HeaderAuthAnalyzer.new(email).analyze rescue puts("  header_auth: SKIPPED (#{$!.message})")
    Analysis::ContentAnalyzer.new(email).analyze rescue puts("  content_analysis: SKIPPED (#{$!.message})")
    Analysis::SenderReputationAnalyzer.new(email).analyze rescue puts("  sender_reputation: SKIPPED (#{$!.message})")
    Analysis::ExternalApiAnalyzer.new(email).analyze rescue puts("  external_api: SKIPPED (#{$!.message})")
    Analysis::EntityVerificationAnalyzer.new(email).analyze rescue puts("  entity_verification: SKIPPED (#{$!.message})")

    email.analysis_layers.reload.order(:layer_name).each do |l|
      puts "  #{l.layer_name}: #{l.score}/100 (confidence: #{l.confidence})"
    end

    # Run LLM consultations synchronously
    puts "\n--- Running LLM consultations ---"
    prior = email.analysis_layers.where(status: "completed")
    prompt_builder = Analysis::Prompts::FraudAnalysisPrompt.new(email, prior)
    system_prompt = prompt_builder.build_system
    user_content = prompt_builder.build_user

    Analysis::LlmAnalyzer::MODELS.each do |provider, model_id|
      begin
        chat = RubyLLM.chat(model: model_id)
        chat.with_instructions(system_prompt)
        resp = chat.ask(user_content)
        text = resp.content.to_s
        si = text.index("{")
        ei = text.rindex("}")
        data = (si && ei) ? (JSON.parse(text[si..ei]) rescue {}) : {}
        validator = Analysis::LlmFindingValidator.new(email)
        findings = validator.validate_findings(Array(data["key_findings"]).map(&:to_s).first(10))
        valid_verdicts = %w[legitimate suspicious_likely_ok suspicious_likely_fraud fraudulent]
        verdict = valid_verdicts.include?(data["verdict"]) ? data["verdict"] : "suspicious_likely_fraud"
        v = email.llm_verdicts.find_or_initialize_by(provider: provider)
        v.update!(
          model_id: model_id,
          score: data["score"]&.to_i&.clamp(0, 100),
          verdict: verdict,
          confidence: data["confidence"]&.to_f&.clamp(0.0, 1.0),
          reasoning: data["reasoning"].to_s,
          key_findings: findings,
          content_patterns: {},
          prompt_tokens: resp.input_tokens,
          completion_tokens: resp.output_tokens,
          response_time_seconds: 0
        )
        puts "  #{provider}: score=#{v.score} verdict=#{v.verdict} confidence=#{v.confidence}"
      rescue => e
        puts "  #{provider}: ERROR #{e.message[0..80]}"
      end
    end

    # Finalize LLM consensus and aggregate scores
    Analysis::LlmAnalyzer.finalize(email)
    result = Analysis::ScoreAggregator.new(email).aggregate
    score = result&.dig(:score) || 50
    verdict = result&.dig(:verdict) || "unknown"

    puts "\n--- Final result ---"
    puts "  SCORE: #{score}/100  VERDICT: #{verdict}#{score < 30 ? '  >>> BYPASS!' : ''}"

    # Generate and send report
    renderer = ReportRenderer.new(email)
    report = email.build_analysis_report
    report.update!(report_html: renderer.to_html, report_text: renderer.to_text, status: "generated")
    AnalysisReportMailer.report(email).deliver_now
    report.update!(status: "sent", sent_at: Time.current)
    email.update!(status: "completed")

    puts "  Report sent to #{submitter}"
  end
end
