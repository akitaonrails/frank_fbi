module CommunityReporting
  class SpamcopForwarder
    def initialize
      @submission_address = ENV.fetch("SPAMCOP_SUBMISSION_ADDRESS", "")
    end

    def forward(email)
      return nil if @submission_address.blank?
      return nil if email.raw_source.blank?

      mail = Mail.new do |m|
        m.from    = ENV.fetch("GMAIL_USERNAME", "")
        m.to      = @submission_address
        m.subject = "SpamCop Report: #{email.subject}".truncate(200)
      end

      mail.attachments["original.eml"] = {
        mime_type: "message/rfc822",
        content: email.raw_source
      }

      mail.deliver

      { forwarded_to: @submission_address, message_id: email.message_id }
    rescue => e
      Rails.logger.error("SpamcopForwarder: Failed to forward email #{email.id}: #{e.message}")
      nil
    end
  end
end
