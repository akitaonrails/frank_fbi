class EmailParsingJob < ApplicationJob
  queue_as :default

  def perform(email_id)
    email = Email.find(email_id)
    return unless email.status == "pending"

    email.update!(status: "parsing")

    parser = EmailParser.new(email.raw_source)
    parsed = parser.parse

    attrs = {
      subject: parsed[:subject],
      from_address: parsed[:from_address],
      from_name: parsed[:from_name],
      reply_to_address: parsed[:reply_to_address],
      sender_domain: parsed[:sender_domain],
      body_text: parsed[:body_text],
      body_html: parsed[:body_html],
      raw_headers: parsed[:raw_headers],
      extracted_urls: parsed[:extracted_urls],
      extracted_emails: parsed[:extracted_emails],
      attachments_info: parsed[:attachments_info],
      received_at: parsed[:received_at],
      status: "analyzing"
    }

    if trusted_domain?(parsed[:sender_domain])
      attrs[:pipeline_type] = "contact_triage"
    end

    email.update!(attrs)

    # Start analysis pipeline
    email.pipeline_orchestrator.advance(email)
  rescue => e
    email&.update(status: "failed")
    Rails.logger.error("EmailParsingJob failed for email #{email_id}: #{e.message}")
    raise
  end

  private

  def trusted_domain?(domain)
    return false if domain.blank?

    trusted = ENV.fetch("TRUSTED_DOMAINS", "").split(",").map(&:strip).reject(&:blank?)
    trusted.any? { |d| domain.downcase == d.downcase }
  end
end
