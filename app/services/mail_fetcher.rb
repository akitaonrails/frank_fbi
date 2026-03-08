require "net/imap"
require "net/http"
require "uri"

class MailFetcher
  IDLE_TIMEOUT = 300       # Re-issue IDLE every 5 min (Gmail drops after ~10 min)
  MIN_RECONNECT_DELAY = 2  # Initial backoff
  MAX_RECONNECT_DELAY = 120 # Cap at 2 minutes
  HTTP_TIMEOUT = 30        # Timeout for relay HTTP calls
  IMAP_OPEN_TIMEOUT = 15   # Timeout for IMAP connection
  MAX_MESSAGE_SIZE = 25 * 1024 * 1024 # Skip messages > 25 MB

  def initialize
    @host = ENV.fetch("GMAIL_IMAP_HOST", "imap.gmail.com")
    @port = 993
    @username = ENV.fetch("GMAIL_USERNAME")
    @password = ENV.fetch("GMAIL_PASSWORD")
    @ingress_password = ENV.fetch("RAILS_INBOUND_EMAIL_PASSWORD")
    @app_host = ENV.fetch("APP_HOST", "http://localhost:3000")
    @running = true
    @consecutive_failures = 0
  end

  def run
    trap_signals
    Rails.logger.info("MailFetcher: Starting IMAP IDLE loop")

    while @running
      run_idle_session
      @consecutive_failures = 0
    rescue Net::IMAP::NoResponseError, Net::IMAP::ByeResponseError => e
      handle_reconnect("IMAP server said goodbye: #{e.message}")
    rescue Net::IMAP::Error => e
      handle_reconnect("IMAP error: #{e.message}")
    rescue IOError, Errno::ECONNRESET, Errno::EPIPE, Errno::ETIMEDOUT,
           Errno::ECONNREFUSED, Errno::ENETUNREACH, Errno::EHOSTUNREACH => e
      handle_reconnect("Network error: #{e.class} - #{e.message}")
    rescue OpenSSL::SSL::SSLError => e
      handle_reconnect("SSL error: #{e.message}")
    rescue => e
      handle_reconnect("Unexpected error: #{e.class} - #{e.message}")
    end

    Rails.logger.info("MailFetcher: Stopped")
  end

  def stop
    @running = false
    @imap&.idle_done rescue nil
  end

  def fetch_once
    with_imap { |imap| fetch_and_relay(imap) }
  end

  private

  def trap_signals
    %w[INT TERM].each do |sig|
      Signal.trap(sig) do
        @running = false
        @imap&.idle_done rescue nil
      end
    end
  end

  def handle_reconnect(reason)
    @consecutive_failures += 1
    delay = reconnect_delay
    Rails.logger.error("MailFetcher: #{reason}. Reconnecting in #{delay}s (attempt #{@consecutive_failures})")
    sleep delay
  end

  def reconnect_delay
    [MIN_RECONNECT_DELAY * (2**(@consecutive_failures - 1)), MAX_RECONNECT_DELAY].min
  end

  def run_idle_session
    with_imap do |imap|
      fetch_and_relay(imap)
      @consecutive_failures = 0 # Connection is healthy

      while @running
        Rails.logger.debug("MailFetcher: Entering IDLE mode")
        got_mail = idle_wait(imap)

        if got_mail
          Rails.logger.info("MailFetcher: IDLE notified of new mail")
          fetch_and_relay(imap)
        end

        # Send NOOP as keepalive after each IDLE cycle to verify connection
        imap.noop
      end
    end
  end

  def idle_wait(imap)
    got_mail = false

    imap.idle(IDLE_TIMEOUT) do |resp|
      if resp.is_a?(Net::IMAP::UntaggedResponse) && resp.name == "EXISTS"
        got_mail = true
        imap.idle_done
      end
    end

    got_mail
  end

  def with_imap
    @imap = Net::IMAP.new(@host, port: @port, ssl: true, open_timeout: IMAP_OPEN_TIMEOUT)
    @imap.login(@username, @password)
    @imap.select("INBOX")
    Rails.logger.info("MailFetcher: Connected to #{@host} as #{@username}")
    yield @imap
  ensure
    disconnect_imap
  end

  def disconnect_imap
    @imap&.logout rescue nil
    @imap&.disconnect rescue nil
    @imap = nil
  end

  def fetch_and_relay(imap)
    message_ids = imap.search(["UNSEEN"])

    if message_ids.empty?
      Rails.logger.debug("MailFetcher: No new messages")
      return
    end

    Rails.logger.info("MailFetcher: Found #{message_ids.size} new message(s)")

    message_ids.each do |msg_id|
      break unless @running
      process_message(imap, msg_id)
    end
  end

  def process_message(imap, msg_id)
    # Fetch envelope + size first to decide whether to download full body
    data = imap.fetch(msg_id, ["ENVELOPE", "RFC822.SIZE"]).first
    envelope = data.attr["ENVELOPE"]
    size = data.attr["RFC822.SIZE"].to_i

    if size > MAX_MESSAGE_SIZE
      Rails.logger.warn("MailFetcher: Skipping oversized message (#{size} bytes): #{envelope.subject}")
      imap.store(msg_id, "+FLAGS", [:Seen])
      return
    end

    rfc822 = imap.fetch(msg_id, "RFC822").first.attr["RFC822"]
    Rails.logger.info("MailFetcher: Processing message: #{envelope.subject} (#{size} bytes)")

    if relay_to_action_mailbox(rfc822)
      imap.store(msg_id, "+FLAGS", [:Seen])
    end
  rescue Net::IMAP::Error => e
    # IMAP-level errors during message processing bubble up to reconnect
    raise
  rescue => e
    Rails.logger.error("MailFetcher: Failed to process message #{msg_id}: #{e.class} - #{e.message}")
  end

  def relay_to_action_mailbox(rfc822)
    uri = URI("#{@app_host}/rails/action_mailbox/relay/inbound_emails")
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = uri.scheme == "https"
    http.open_timeout = HTTP_TIMEOUT
    http.read_timeout = HTTP_TIMEOUT
    http.write_timeout = HTTP_TIMEOUT

    request = Net::HTTP::Post.new(uri)
    request.basic_auth("actionmailbox", @ingress_password)
    request.content_type = "message/rfc822"
    request.body = rfc822

    response = http.request(request)

    if response.is_a?(Net::HTTPSuccess) || response.is_a?(Net::HTTPNoContent)
      true
    else
      Rails.logger.error("MailFetcher: Action Mailbox relay returned #{response.code}: #{response.body}")
      false
    end
  rescue Errno::ECONNREFUSED, Errno::ETIMEDOUT, Net::OpenTimeout, Net::ReadTimeout => e
    Rails.logger.error("MailFetcher: Relay failed (app unreachable): #{e.class} - #{e.message}")
    false
  end
end
