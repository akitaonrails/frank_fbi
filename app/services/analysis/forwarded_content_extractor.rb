module Analysis
  class ForwardedContentExtractor
    FORWARDING_MARKERS = [
      /^-{5,}\s*Forwarded message\s*-{5,}/i,
      /^-{5,}\s*Original Message\s*-{5,}/i,
      /^-{5,}\s*Mensagem encaminhada\s*-{5,}/i,
      /^-{5,}\s*Mensaje reenviado\s*-{5,}/i
    ].freeze

    # RFC 3676 signature delimiter: "-- " on its own line (handles \r\n and \n)
    SIGNATURE_DELIMITER = /^-- ?\r?\n/m

    def initialize(body_text)
      @body_text = body_text.to_s
    end

    def extract
      marker_pos = find_forwarding_marker
      return { suspect_text: @body_text, submitter_text: nil, forwarded: false } unless marker_pos

      candidate = @body_text[marker_pos..]
      suspect_text = strip_trailing_signature(candidate)
      submitter_text = @body_text[0...marker_pos].strip.presence

      { suspect_text: suspect_text.strip, submitter_text: submitter_text, forwarded: true }
    end

    private

    def find_forwarding_marker
      FORWARDING_MARKERS.each do |pattern|
        match = @body_text.match(pattern)
        return match.begin(0) if match
      end
      nil
    end

    def strip_trailing_signature(text)
      # Find the last RFC 3676 signature delimiter ("-- \n" or "-- \r\n")
      # and remove everything after it (submitter's email signature)
      parts = text.split(SIGNATURE_DELIMITER)
      return text if parts.size <= 1

      # Keep everything before the last delimiter
      parts[0..-2].join("-- \n").rstrip
    end
  end
end
