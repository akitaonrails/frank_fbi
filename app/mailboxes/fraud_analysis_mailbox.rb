class FraudAnalysisMailbox < ApplicationMailbox
  def process
    submitter = mail.from&.first || mail["X-Original-Sender"]&.to_s || "unknown@unknown.com"

    # Check if this is a forwarded email - try to extract the original
    raw_source = inbound_email.raw_email.download

    email = Email.create!(
      message_id: extract_message_id,
      submitter_email: submitter.downcase.strip,
      status: "pending",
      raw_source: raw_source
    )

    EmailParsingJob.perform_later(email.id)
  rescue ActiveRecord::RecordNotUnique
    # Already processed this email
    Rails.logger.info("FraudAnalysisMailbox: Duplicate email #{mail.message_id}")
    bounced!
  end

  private

  def extract_message_id
    mail.message_id || SecureRandom.uuid
  end
end
