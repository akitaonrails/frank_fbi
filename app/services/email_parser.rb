require "digest"
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
    context = detect_message_context
    analysis_mail = context[:mail]
    analysis_raw_source = context[:raw_source]
    body_text = context[:body_text]
    body_html = context[:body_html]
    from_addr = context[:from_address] || extract_from_address(analysis_mail)
    from_nm = context[:from_name] || extract_from_name(analysis_mail)
    subject = context[:subject] || analysis_mail.subject&.strip
    reply_to = context[:reply_to_address] || extract_reply_to(analysis_mail)
    received_at = context[:received_at] || analysis_mail.date&.to_time

    {
      message_id: extract_message_id(analysis_mail),
      subject: subject,
      from_address: from_addr,
      from_name: from_nm,
      reply_to_address: reply_to,
      sender_domain: from_addr&.split("@")&.last,
      body_text: body_text,
      body_html: body_html,
      raw_headers: extract_raw_headers(analysis_raw_source),
      analysis_raw_source: analysis_raw_source,
      extracted_urls: extract_urls(body_text, body_html),
      extracted_emails: extract_emails_from_body(body_text, body_html),
      attachments_info: extract_attachments_info(analysis_mail),
      received_at: received_at
    }
  end

  private

  def detect_message_context
    detection = ForwardingSourceDetector.new(raw_source).detect

    case detection[:mode]
    when "attached_message"
      build_attached_message_context(detection[:attached_raw_source])
    else
      build_outer_message_context(detection[:mode])
    end
  end

  def build_attached_message_context(attached_raw_source)
    attached_mail = Mail.new(attached_raw_source)

    {
      mode: "attached_message",
      mail: attached_mail,
      raw_source: attached_raw_source,
      body_text: extract_body_text(attached_mail),
      body_html: extract_body_html(attached_mail),
      from_address: extract_from_address(attached_mail),
      from_name: extract_from_name(attached_mail),
      reply_to_address: extract_reply_to(attached_mail),
      subject: attached_mail.subject&.strip,
      received_at: attached_mail.date&.to_time
    }
  rescue => e
    Rails.logger.warn("EmailParser: Failed to parse attached original message: #{e.message}")
    build_outer_message_context("direct")
  end

  def build_outer_message_context(mode)
    outer_body_text = extract_body_text(mail)
    outer_body_html = extract_body_html(mail)
    body_text = outer_body_text
    body_html = outer_body_html
    forwarded = nil
    subject = mail.subject&.strip
    received_at = mail.date&.to_time

    if mode == "inline_forward"
      extractor = Analysis::ForwardedContentExtractor.new(outer_body_text).extract
      body_text = extractor[:suspect_text]
      body_html = strip_submitter_signature_html(outer_body_html)
      forward_blob = [outer_body_text, outer_body_html].compact.join("\n")
      forwarded = detect_forwarded_message(forward_blob)
      subject = detect_forwarded_subject(outer_body_text) || subject
      received_at = parse_forwarded_date(outer_body_text) || received_at
    else
      forwarded = detect_contact_form_sender([outer_body_text, outer_body_html].compact.join("\n"))
    end

    {
      mode: forwarded ? (mode == "inline_forward" ? mode : "contact_form") : mode,
      mail: mail,
      raw_source: raw_source,
      body_text: body_text,
      body_html: body_html,
      from_address: forwarded&.dig(:address),
      from_name: forwarded&.dig(:name),
      subject: subject,
      received_at: received_at
    }
  end

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
      next if address == extract_from_address(mail)

      return { address: address, name: name.presence }
    end

    nil
  end

  def detect_contact_form_sender(text)
    patterns = [
      /^[\s>]*(?:e[\-\s]?mail|reply[\-\s]?(?:to[\-\s]?)?e?mail|sender(?:'s)?\s+e?mail|contact\s+e?mail|from)\s*[:=]\s*<?([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})>?\s*$/mi,
      /\b(?:e[\-\s]?mail|reply[\-\s]?(?:to[\-\s]?)?e?mail|sender(?:'s)?\s+e?mail|contact\s+e?mail)\s*[:=]\s*<?([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})>?/mi
    ]

    html_patterns = [
      %r{<(?:td|th|dt|span|div|label)[^>]*>\s*(?:e[\-\s]?mail|sender)\s*:?\s*</(?:td|th|dt|span|div|label)>\s*<(?:td|dd|span|div)[^>]*>\s*<?([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})>?\s*</}mi
    ]

    name_match = text.match(/^[\s>]*(?:name|full[\-\s]?name|sender(?:'s)?\s+name|nome|nombre)\s*[:=]\s*(.+?)$/mi)

    (patterns + html_patterns).each do |pattern|
      match = text.match(pattern)
      next unless match

      address = match[1]&.downcase&.strip
      next if address == extract_from_address(mail)

      name = name_match ? name_match[1]&.strip&.gsub(/^["']|["']$/, "") : nil
      return { address: address, name: name.presence }
    end

    nil
  end

  def extract_message_id(mail_object = mail)
    mid = mail_object.message_id
    mid.present? ? mid.strip : SecureRandom.uuid
  end

  def extract_from_address(mail_object = mail)
    return nil if mail_object.from.blank?

    mail_object.from.first&.downcase&.strip
  end

  def extract_from_name(mail_object = mail)
    return nil if mail_object[:from].blank?

    mail_object[:from].addrs&.first&.display_name&.strip
  end

  def extract_reply_to(mail_object = mail)
    return nil if mail_object.reply_to.blank?

    mail_object.reply_to.first&.downcase&.strip
  end

  def extract_body_text(mail_object = mail)
    if mail_object.multipart?
      text_part = mail_object.text_part
      return text_part.decoded.force_encoding("UTF-8") if text_part

      html = extract_body_html(mail_object)
      return strip_html(html) if html
    end

    body = mail_object.body.decoded.force_encoding("UTF-8")
    mail_object.content_type&.include?("text/html") ? strip_html(body) : body
  rescue => e
    Rails.logger.warn("EmailParser: Failed to extract text body: #{e.message}")
    nil
  end

  def extract_body_html(mail_object = mail)
    if mail_object.multipart?
      html_part = mail_object.html_part
      return html_part.decoded.force_encoding("UTF-8") if html_part
    end

    body = mail_object.body.decoded.force_encoding("UTF-8")
    body if mail_object.content_type&.include?("text/html")
  rescue => e
    Rails.logger.warn("EmailParser: Failed to extract HTML body: #{e.message}")
    nil
  end

  def extract_raw_headers(source = raw_source)
    source.to_s.split(/\r?\n\r?\n/, 2).first
  end

  def extract_urls(body_text, body_html)
    [body_text, body_html].compact.join(" ").scan(URL_REGEX).uniq.map { |url| clean_url(url) }.compact.uniq
  end

  def extract_emails_from_body(body_text, body_html)
    [body_text, body_html].compact.join(" ").scan(EMAIL_REGEX).uniq.reject { |email| email.match?(/\.(png|jpg|gif|css)$/i) }
  end

  def extract_attachments_info(mail_object = mail)
    mail_object.attachments.reject { |attachment| eml_attachment?(attachment) }.map do |attachment|
      decoded = attachment.body.decoded
      {
        filename: attachment.filename,
        content_type: attachment.content_type,
        size: decoded.bytesize,
        sha256: Digest::SHA256.hexdigest(decoded)
      }
    end
  rescue => e
    Rails.logger.warn("EmailParser: Failed to extract attachments: #{e.message}")
    []
  end

  def detect_forwarded_subject(text)
    text.to_s[/^Subject:\s*(.+)$/i, 1]&.strip
  end

  def parse_forwarded_date(text)
    date_text = text.to_s[/^Date:\s*(.+)$/i, 1]
    return nil if date_text.blank?

    Time.zone.parse(date_text) || Time.parse(date_text)
  rescue
    nil
  end

  def eml_attachment?(attachment)
    attachment.mime_type.to_s.downcase == "message/rfc822" || attachment.filename.to_s.downcase.end_with?(".eml")
  end

  def strip_submitter_signature_html(html)
    return nil if html.blank?

    html.to_s.sub(/<span class=["']gmail_signature_prefix["'][\s\S]*\z/i, "")
  end

  def clean_url(url)
    normalized = url.gsub(/[.,;:!?\)>\]]+$/, "")
    URI.parse(normalized)
    normalized
  rescue URI::InvalidURIError
    nil
  end

  def strip_html(html)
    Rails::HTML5::SafeListSanitizer.new.sanitize(html, tags: []).gsub(/\s+/, " ").strip
  rescue StandardError
    html&.gsub(/<[^>]+>/, " ")&.gsub(/\s+/, " ")&.strip
  end
end
