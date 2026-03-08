class AdminCommandMailbox < ApplicationMailbox
  def process
    result = AdminCommandProcessor.new(
      subject: mail.subject,
      body: mail.decoded || mail.body&.decoded || "",
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
end
