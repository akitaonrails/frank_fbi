class ForwardingSourceDetector
  def initialize(raw_source)
    @raw_source = raw_source.to_s
  end

  def detect
    attached_raw_source = extract_attached_raw_source
    return { mode: "attached_message", attached_raw_source: attached_raw_source } if attached_raw_source.present?

    if Analysis::ForwardedContentExtractor.new(outer_text_body).extract[:forwarded]
      return { mode: "inline_forward" }
    end

    { mode: "direct" }
  end

  private

  def outer_mail
    @outer_mail ||= Mail.new(@raw_source)
  end

  def extract_attached_raw_source
    # Primary detection: explicit message/rfc822 or .eml filename.
    part = outer_mail.all_parts.find do |candidate|
      content_type = candidate.mime_type.to_s.downcase
      filename = candidate.filename.to_s.downcase
      content_type == "message/rfc822" || filename.end_with?(".eml")
    end

    if part.nil?
      # Fallback for clients (notably Gmail) that ship the forwarded message
      # as application/octet-stream with no .eml extension. Sniff the body to
      # see if it actually starts with RFC 5322 headers.
      part = outer_mail.all_parts.find do |candidate|
        next if candidate.multipart?
        next if candidate.content_type.to_s.downcase.start_with?("text/")
        looks_like_rfc822?(candidate.body.decoded)
      end
    end

    decoded = part&.decoded
    return nil if decoded.blank?
    return nil unless looks_like_rfc822?(decoded)
    decoded
  rescue
    nil
  end

  # Cheap RFC 5322 sniff: must contain at least one of the canonical envelope
  # headers near the top of the payload. We don't try to fully validate — Mail.new
  # will do that downstream.
  def looks_like_rfc822?(content)
    return false if content.blank?

    head = content.byteslice(0, 4096).to_s
    head.force_encoding("ASCII-8BIT")
    return false unless head.match?(/^(From|Received|Return-Path|Message-ID|Subject|To|Delivered-To):/i)

    # At least two distinct header-style lines to avoid false positives on
    # plaintext bodies that happen to contain "From: " somewhere.
    head.scan(/^[A-Za-z][A-Za-z0-9\-]+:\s/).size >= 2
  end

  def outer_text_body
    if outer_mail.multipart?
      text_part = outer_mail.text_part
      return safe_decode(text_part) if text_part
    end

    safe_decode(outer_mail)
  rescue
    ""
  end

  def safe_decode(part)
    bytes = part.body.decoded.to_s.dup
    bytes.force_encoding("UTF-8")
    bytes.valid_encoding? ? bytes : bytes.scrub("?")
  end
end
