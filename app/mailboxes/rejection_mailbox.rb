class RejectionMailbox < ApplicationMailbox
  def process
    sender = mail.from&.first
    return unless sender.present?

    AdminMailer.rejection_notice(
      sender,
      mail.subject || "(no subject)"
    ).deliver_later
  end
end
