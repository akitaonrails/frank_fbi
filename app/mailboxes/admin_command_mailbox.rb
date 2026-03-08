class AdminCommandMailbox < ApplicationMailbox
  def process
    result = AdminCommandProcessor.new(
      subject: mail.subject,
      body: extract_body,
      admin_email: admin_email
    ).process

    AdminMailer.command_result(
      admin_email,
      result.subject,
      result.body_html,
      result.body_text
    ).deliver_later
  end

  private

  def admin_email
    mail.from&.first&.downcase&.strip
  end

  def extract_body
    if mail.multipart?
      mail.text_part&.decoded || mail.html_part&.decoded || ""
    else
      mail.body&.decoded || ""
    end.force_encoding("UTF-8")
  rescue => e
    Rails.logger.warn("AdminCommandMailbox: Failed to decode body: #{e.message}")
    ""
  end
end
