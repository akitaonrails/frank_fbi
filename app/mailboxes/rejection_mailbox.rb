class RejectionMailbox < ApplicationMailbox
  def process
    sender = mail.from&.first
    return unless sender.present?

    subject = mail.subject || "(no subject)"

    if AllowedSender.authorized?(sender) && AllowedSender.over_rate_limit?(sender)
      AdminMailer.rate_limit_notice(sender, subject).deliver_later
    else
      AdminMailer.rejection_notice(sender, subject).deliver_later
    end
  end
end
