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
    part = outer_mail.all_parts.find do |candidate|
      content_type = candidate.mime_type.to_s.downcase
      filename = candidate.filename.to_s.downcase
      content_type == "message/rfc822" || filename.end_with?(".eml")
    end

    part&.decoded
  rescue
    nil
  end

  def outer_text_body
    if outer_mail.multipart?
      text_part = outer_mail.text_part
      return text_part.decoded.force_encoding("UTF-8") if text_part
    end

    outer_mail.body.decoded.force_encoding("UTF-8")
  rescue
    ""
  end
end
