class AdminCommandProcessor
  COMMANDS = %w[add remove list stats].freeze

  Result = Struct.new(:command, :success, :subject, :body_text, :body_html, keyword_init: true)

  def initialize(subject:, body:, admin_email:)
    @subject = subject.to_s.downcase.strip
    @body = body.to_s.strip
    @admin_email = admin_email
  end

  def process
    command = detect_command
    return unknown_command_result unless command

    send(:"process_#{command}")
  end

  private

  def detect_command
    COMMANDS.find { |cmd| @subject.include?(cmd) }
  end

  def process_add
    emails = extract_emails
    return empty_emails_result("add") if emails.empty?

    added = []
    already_existed = []

    emails.each do |email|
      sender = AllowedSender.find_or_initialize_by(email_address: email)
      if sender.new_record?
        sender.added_by = @admin_email
        sender.save!
        added << email
      elsif !sender.active?
        sender.update!(active: true, added_by: @admin_email)
        added << email
      else
        already_existed << email
      end
    end

    lines = []
    lines << "Added: #{added.join(', ')}" if added.any?
    lines << "Already existed: #{already_existed.join(', ')}" if already_existed.any?
    body = lines.join("\n")

    Result.new(
      command: "add",
      success: true,
      subject: "Re: Senders Added (#{added.size} new, #{already_existed.size} existing)",
      body_text: body,
      body_html: "<p>#{body.gsub("\n", "<br>")}</p>"
    )
  end

  def process_remove
    emails = extract_emails
    return empty_emails_result("remove") if emails.empty?

    removed = []
    not_found = []

    emails.each do |email|
      sender = AllowedSender.find_by(email_address: email)
      if sender&.active?
        sender.update!(active: false)
        removed << email
      else
        not_found << email
      end
    end

    lines = []
    lines << "Removed: #{removed.join(', ')}" if removed.any?
    lines << "Not found or already inactive: #{not_found.join(', ')}" if not_found.any?
    body = lines.join("\n")

    Result.new(
      command: "remove",
      success: true,
      subject: "Re: Senders Removed (#{removed.size} removed)",
      body_text: body,
      body_html: "<p>#{body.gsub("\n", "<br>")}</p>"
    )
  end

  def process_list
    senders = AllowedSender.active.order(:email_address)

    if senders.empty?
      body = "No allowed senders configured."
    else
      body = "Allowed senders (#{senders.size}):\n\n"
      body += senders.map { |s| "- #{s.email_address} (added by #{s.added_by || 'unknown'}, #{s.created_at.strftime('%Y-%m-%d')})" }.join("\n")
    end

    html_body = "<p>Allowed senders (#{senders.size}):</p>"
    if senders.any?
      html_body += "<ul>"
      html_body += senders.map { |s| "<li>#{ERB::Util.html_escape(s.email_address)} (added by #{ERB::Util.html_escape(s.added_by || 'unknown')}, #{s.created_at.strftime('%Y-%m-%d')})</li>" }.join
      html_body += "</ul>"
    end

    Result.new(
      command: "list",
      success: true,
      subject: "Re: Allowed Senders List (#{senders.size})",
      body_text: body,
      body_html: html_body
    )
  end

  def process_stats
    total_emails = Email.count
    completed = Email.completed.count
    pending = Email.pending.count
    failed = Email.failed.count
    fraudulent = Email.fraudulent.count
    allowed_senders = AllowedSender.active.count

    avg_score = Email.where.not(final_score: nil).average(:final_score)&.round(1) || "N/A"

    verdict_counts = Email.where.not(verdict: nil).group(:verdict).count

    body = <<~TEXT
      === Frank FBI System Stats ===

      Emails: #{total_emails} total
        - Completed: #{completed}
        - Pending: #{pending}
        - Failed: #{failed}

      Verdicts:
        - Legitimate: #{verdict_counts['legitimate'] || 0}
        - Likely OK: #{verdict_counts['suspicious_likely_ok'] || 0}
        - Suspicious: #{verdict_counts['suspicious_likely_fraud'] || 0}
        - Fraudulent: #{verdict_counts['fraudulent'] || 0}

      Average Score: #{avg_score}/100
      Allowed Senders: #{allowed_senders}
    TEXT

    html_body = "<pre>#{ERB::Util.html_escape(body)}</pre>"

    Result.new(
      command: "stats",
      success: true,
      subject: "Re: Frank FBI Stats",
      body_text: body,
      body_html: html_body
    )
  end

  def extract_emails
    @body.scan(/[\w+\-.]+@[a-z\d\-]+(\.[a-z\d\-]+)*\.[a-z]+/i).flatten
    # The scan with groups returns groups, use a different approach
    @body.to_enum(:scan, /[\w+\-.]+@[a-z\d\-]+(?:\.[a-z\d\-]+)*\.[a-z]+/i).map { Regexp.last_match[0] }
      .map(&:downcase)
      .map(&:strip)
      .uniq
  end

  def unknown_command_result
    Result.new(
      command: "unknown",
      success: false,
      subject: "Re: Unknown Command",
      body_text: "Unknown command. Available commands: add, remove, list, stats\n\nUse these as the email subject.",
      body_html: "<p>Unknown command. Available commands: <strong>add</strong>, <strong>remove</strong>, <strong>list</strong>, <strong>stats</strong></p><p>Use these as the email subject.</p>"
    )
  end

  def empty_emails_result(command)
    Result.new(
      command: command,
      success: false,
      subject: "Re: No Email Addresses Found",
      body_text: "No email addresses found in the message body. Please include one email address per line.",
      body_html: "<p>No email addresses found in the message body. Please include one email address per line.</p>"
    )
  end
end
