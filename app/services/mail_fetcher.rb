require "net/imap"
require "net/http"
require "uri"

class MailFetcher
  POLL_INTERVAL = 30 # seconds

  def initialize
    @host = ENV.fetch("GMAIL_IMAP_HOST", "imap.gmail.com")
    @port = 993
    @username = ENV.fetch("GMAIL_USERNAME")
    @password = ENV.fetch("GMAIL_PASSWORD")
    @ingress_password = ENV.fetch("ACTION_MAILBOX_INGRESS_PASSWORD")
    @app_host = ENV.fetch("APP_HOST", "http://localhost:3000")
  end

  def run
    Rails.logger.info("MailFetcher: Starting IMAP polling loop (every #{POLL_INTERVAL}s)")

    loop do
      fetch_and_relay
      sleep POLL_INTERVAL
    rescue => e
      Rails.logger.error("MailFetcher: Error in polling loop: #{e.message}")
      sleep POLL_INTERVAL
    end
  end

  def fetch_once
    fetch_and_relay
  end

  private

  def fetch_and_relay
    imap = Net::IMAP.new(@host, port: @port, ssl: true)
    imap.login(@username, @password)
    imap.select("INBOX")

    # Search for unread messages
    message_ids = imap.search(["UNSEEN"])

    if message_ids.empty?
      Rails.logger.debug("MailFetcher: No new messages")
      return
    end

    Rails.logger.info("MailFetcher: Found #{message_ids.size} new message(s)")

    message_ids.each do |msg_id|
      process_message(imap, msg_id)
    end
  ensure
    imap&.logout
    imap&.disconnect
  end

  def process_message(imap, msg_id)
    envelope = imap.fetch(msg_id, "ENVELOPE").first.attr["ENVELOPE"]
    rfc822 = imap.fetch(msg_id, "RFC822").first.attr["RFC822"]

    Rails.logger.info("MailFetcher: Processing message: #{envelope.subject}")

    relay_to_action_mailbox(rfc822)

    # Mark as read
    imap.store(msg_id, "+FLAGS", [:Seen])
  rescue => e
    Rails.logger.error("MailFetcher: Failed to process message #{msg_id}: #{e.message}")
  end

  def relay_to_action_mailbox(rfc822)
    uri = URI("#{@app_host}/rails/action_mailbox/relay/inbound_emails")
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = uri.scheme == "https"

    request = Net::HTTP::Post.new(uri)
    request.basic_auth("actionmailbox", @ingress_password)
    request.content_type = "message/rfc822"
    request.body = rfc822

    response = http.request(request)

    unless response.is_a?(Net::HTTPSuccess) || response.is_a?(Net::HTTPNoContent)
      Rails.logger.error("MailFetcher: Action Mailbox relay returned #{response.code}: #{response.body}")
    end
  end
end
