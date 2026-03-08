class ApplicationMailbox < ActionMailbox::Base
  routing ->(inbound_email) { admin_email?(inbound_email) } => :admin_command
  routing ->(inbound_email) { allowed_sender?(inbound_email) } => :fraud_analysis
  routing :all => :rejection

  private

  def self.admin_email?(inbound_email)
    admin = ENV["ADMIN_EMAIL"]&.downcase&.strip
    return false if admin.blank?

    sender = inbound_email.mail.from&.first&.downcase&.strip
    sender == admin
  end

  def self.allowed_sender?(inbound_email)
    sender = inbound_email.mail.from&.first&.downcase&.strip
    return false if sender.blank?

    AllowedSender.authorized?(sender)
  end
end
