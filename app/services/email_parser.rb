require "mail"
require "uri"

class EmailParser
  URL_REGEX = %r{https?://[^\s<>"'\)]+}i
  EMAIL_REGEX = /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/

  attr_reader :mail, :raw_source

  def initialize(raw_source)
    @raw_source = raw_source
    @mail = Mail.new(raw_source)
  end

  def parse
    forwarded = detect_forwarded_sender
    from_addr = forwarded&.dig(:address) || extract_from_address
    from_nm = forwarded&.dig(:name) || extract_from_name

    {
      message_id: extract_message_id,
      subject: mail.subject&.strip,
      from_address: from_addr,
      from_name: from_nm,
      reply_to_address: extract_reply_to,
      sender_domain: from_addr&.split("@")&.last,
      body_text: extract_body_text,
      body_html: extract_body_html,
      raw_headers: extract_raw_headers,
      extracted_urls: extract_urls,
      extracted_emails: extract_emails_from_body,
      attachments_info: extract_attachments_info,
      received_at: mail.date&.to_time
    }
  end

  private

  # Detect the original sender from forwarded emails or contact form submissions.
  # When a user forwards a spam email, mail.from is the forwarder (the submitter),
  # not the original sender we want to analyze. Similarly, contact form emails
  # come from a system address but embed the actual sender's email in the body.
  def detect_forwarded_sender
    text = [extract_body_text, extract_body_html].compact.join("\n")

    detect_forwarded_message(text) || detect_contact_form_sender(text)
  end

  # Gmail: "---------- Forwarded message ---------\nFrom: Name <email@domain>"
  # Outlook: "-------- Original Message --------\nFrom: Name <email@domain>"
  # Generic: "From: Name <email@domain>" after a forwarding marker
  def detect_forwarded_message(text)
    patterns = [
      /[-]+\s*Forwarded message\s*[-]+.*?From:\s*(?:(.+?)\s+)?<?([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})>?/mi,
      /[-]+\s*Original Message\s*[-]+.*?From:\s*(?:(.+?)\s+)?<?([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})>?/mi,
      /^>?\s*From:\s*(?:(.+?)\s+)?<?([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})>?\s*$/mi
    ]

    patterns.each do |pattern|
      match = text.match(pattern)
      next unless match

      address = match[2]&.downcase&.strip
      name = match[1]&.strip&.gsub(/^["']|["']$/, "")

      next if address == extract_from_address

      return { address: address, name: name.presence }
    end

    nil
  end

  # Contact form emails embed the sender's email in the body with labels like:
  #   "Email: scammer@evil.com", "E-mail: ...", "From: ...", "Reply email: ..."
  #   "Sender: ...", "Contact email: ...", or HTML form fields
  def detect_contact_form_sender(text)
    patterns = [
      /^[\s>]*(?:e[\-\s]?mail|reply[\-\s]?(?:to[\-\s]?)?e?mail|sender(?:'s)?\s+e?mail|contact\s+e?mail|from)\s*[:=]\s*<?([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})>?\s*$/mi,
      /\b(?:e[\-\s]?mail|reply[\-\s]?(?:to[\-\s]?)?e?mail|sender(?:'s)?\s+e?mail|contact\s+e?mail)\s*[:=]\s*<?([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})>?/mi
    ]

    # Also check for common HTML form field patterns: <td>Email</td><td>value@email.com</td>
    html_patterns = [
      %r{<(?:td|th|dt|span|div|label)[^>]*>\s*(?:e[\-\s]?mail|sender)\s*:?\s*</(?:td|th|dt|span|div|label)>\s*<(?:td|dd|span|div)[^>]*>\s*<?([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})>?\s*</}mi
    ]

    all_patterns = patterns + html_patterns

    # Also try "Name: ... \n Email: ..." pattern common in contact forms
    name_match = text.match(/^[\s>]*(?:name|full[\-\s]?name|sender(?:'s)?\s+name|nome|nombre)\s*[:=]\s*(.+?)$/mi)

    all_patterns.each do |pattern|
      match = text.match(pattern)
      next unless match

      address = match[1]&.downcase&.strip
      next if address == extract_from_address

      name = name_match ? name_match[1]&.strip&.gsub(/^["']|["']$/, "") : nil
      return { address: address, name: name.presence }
    end

    nil
  end

  def extract_message_id
    mid = mail.message_id
    mid.present? ? mid.strip : SecureRandom.uuid
  end

  def extract_from_address
    return nil if mail.from.blank?

    mail.from.first&.downcase&.strip
  end

  def extract_from_name
    return nil if mail[:from].blank?

    addr = mail[:from].addrs&.first
    addr&.display_name&.strip
  end

  def extract_reply_to
    return nil if mail.reply_to.blank?

    mail.reply_to.first&.downcase&.strip
  end

  def extract_sender_domain
    from = extract_from_address
    return nil unless from

    from.split("@").last
  end

  def extract_body_text
    if mail.multipart?
      text_part = mail.text_part
      return text_part.decoded.force_encoding("UTF-8") if text_part

      # Fallback: strip HTML from HTML part
      html = extract_body_html
      return strip_html(html) if html
    end

    body = mail.body.decoded.force_encoding("UTF-8")
    if mail.content_type&.include?("text/html")
      strip_html(body)
    else
      body
    end
  rescue => e
    Rails.logger.warn("EmailParser: Failed to extract text body: #{e.message}")
    nil
  end

  def extract_body_html
    if mail.multipart?
      html_part = mail.html_part
      return html_part.decoded.force_encoding("UTF-8") if html_part
    end

    body = mail.body.decoded.force_encoding("UTF-8")
    body if mail.content_type&.include?("text/html")
  rescue => e
    Rails.logger.warn("EmailParser: Failed to extract HTML body: #{e.message}")
    nil
  end

  def extract_raw_headers
    raw_source.split(/\r?\n\r?\n/, 2).first
  end

  def extract_urls
    text = [extract_body_text, extract_body_html].compact.join(" ")
    urls = text.scan(URL_REGEX).uniq
    urls.map { |u| clean_url(u) }.compact.uniq
  end

  def extract_emails_from_body
    text = [extract_body_text, extract_body_html].compact.join(" ")
    emails = text.scan(EMAIL_REGEX).uniq
    # Exclude the sender and common system addresses
    emails.reject { |e| e.match?(/\.(png|jpg|gif|css)$/i) }
  end

  def extract_attachments_info
    mail.attachments.map do |attachment|
      {
        filename: attachment.filename,
        content_type: attachment.content_type,
        size: attachment.body.decoded.bytesize
      }
    end
  rescue => e
    Rails.logger.warn("EmailParser: Failed to extract attachments: #{e.message}")
    []
  end

  def clean_url(url)
    # Remove trailing punctuation that might be part of text, not URL
    url = url.gsub(/[.,;:!?\)>\]]+$/, "")
    URI.parse(url)
    url
  rescue URI::InvalidURIError
    nil
  end

  def strip_html(html)
    Rails::HTML5::SafeListSanitizer.new.sanitize(html, tags: []).gsub(/\s+/, " ").strip
  rescue
    html&.gsub(/<[^>]+>/, " ")&.gsub(/\s+/, " ")&.strip
  end
end
