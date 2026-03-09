class MessengerTriageMailbox < ApplicationMailbox
  def process
    submitter = mail.from&.first || "unknown@unknown.com"

    raw_source = inbound_email.raw_email.download

    email = Email.create!(
      message_id: extract_message_id,
      submitter_email: submitter.downcase.strip,
      pipeline_type: "messenger_triage",
      status: "pending",
      raw_source: raw_source
    )

    MessengerTriageParsingJob.perform_later(email.id)
  rescue ActiveRecord::RecordNotUnique
    Rails.logger.info("MessengerTriageMailbox: Duplicate email #{mail.message_id}")
    bounced!
  end

  private

  def extract_message_id
    mail.message_id || SecureRandom.uuid
  end
end
