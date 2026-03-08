class ApplicationMailbox < ActionMailbox::Base
  routing ->(inbound_email) { admin_email?(inbound_email) } => :admin_command
  routing ->(inbound_email) { allowed_sender?(inbound_email) } => :fraud_analysis
  routing :all => :rejection

  private

  def self.admin_email?(inbound_email)
    admin = ENV["ADMIN_EMAIL"]&.downcase&.strip
    return false if admin.blank?

    sender = inbound_email.mail.from&.first&.downcase&.strip
    return false unless sender == admin

    unless email_authenticated?(inbound_email)
      Rails.logger.warn("ApplicationMailbox: REJECTED admin impersonation attempt from #{sender} — failed SPF/DKIM")
      return false
    end

    true
  end

  def self.allowed_sender?(inbound_email)
    sender = inbound_email.mail.from&.first&.downcase&.strip
    return false if sender.blank?

    return false unless AllowedSender.authorized?(sender)

    unless email_authenticated?(inbound_email)
      Rails.logger.warn("ApplicationMailbox: REJECTED unauthenticated allowed sender #{sender} — failed SPF/DKIM")
      return false
    end

    true
  end

  # Verify SPF/DKIM via the Authentication-Results header added by the receiving MTA (Gmail).
  # If the header is absent (local dev/testing), allow through.
  # If present and shows failure, reject to prevent From header spoofing.
  def self.email_authenticated?(inbound_email)
    auth_header = inbound_email.mail["Authentication-Results"]&.to_s
    return true if auth_header.blank?

    auth_header.include?("spf=pass") || auth_header.include?("dkim=pass")
  end
end
