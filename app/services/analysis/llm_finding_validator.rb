module Analysis
  class LlmFindingValidator
    BLACKLIST_PATTERNS = [
      /lista[s]?\s*negra/i,
      /blacklist/i,
      /bloqueado.*dnsbl/i,
      /spamhaus/i,
      /uribl/i,
      /barracuda/i,
      /dnsbl/i
    ].freeze

    URL_MALICIOUS_PATTERNS = [
      /url[s]?\s*(maliciosa|perigosa|infectada|detectada)/i,
      /virustotal.*malicio/i,
      /urlhaus.*malicio/i,
      /url[s]?\s*flagged/i,
      /malicious\s*url/i,
      /url[s]?\s*identificada/i
    ].freeze

    ATTACHMENT_PATTERNS = [
      /anexo[s]?\s*(malicioso|perigoso|infectado|suspeito)/i,
      /malicious\s*attachment/i,
      /arquivo[s]?\s*(malicioso|infectado)/i
    ].freeze

    def initialize(email)
      @email = email
      @layers = load_layers
    end

    def validate_findings(findings)
      return findings if findings.blank?

      findings.filter_map do |finding|
        validate_single_finding(finding)
      end
    end

    private

    def load_layers
      @email.analysis_layers.where(status: "completed").index_by(&:layer_name)
    end

    def validate_single_finding(finding)
      return finding if finding.blank?

      if matches_blacklist_claim?(finding)
        validate_blacklist_claim(finding)
      elsif matches_url_malicious_claim?(finding)
        validate_url_malicious_claim(finding)
      elsif matches_attachment_claim?(finding)
        validate_attachment_claim(finding)
      else
        finding
      end
    end

    def matches_blacklist_claim?(finding)
      BLACKLIST_PATTERNS.any? { |pattern| finding.match?(pattern) }
    end

    def matches_url_malicious_claim?(finding)
      URL_MALICIOUS_PATTERNS.any? { |pattern| finding.match?(pattern) }
    end

    def matches_attachment_claim?(finding)
      ATTACHMENT_PATTERNS.any? { |pattern| finding.match?(pattern) }
    end

    def validate_blacklist_claim(finding)
      layer = @layers["sender_reputation"]

      unless layer
        Rails.logger.warn("LlmFindingValidator: Blacklist claim without sender_reputation layer: #{finding}")
        return "[Não verificado] #{finding}"
      end

      actual_hits = layer.details&.dig("blacklist_hits").to_i

      if actual_hits > 0
        finding
      else
        Rails.logger.warn("LlmFindingValidator: HALLUCINATION stripped — blacklist claim with 0 actual hits: #{finding}")
        nil
      end
    end

    def validate_url_malicious_claim(finding)
      layer = @layers["external_api"]

      unless layer
        Rails.logger.warn("LlmFindingValidator: URL malicious claim without external_api layer: #{finding}")
        return "[Não verificado] #{finding}"
      end

      details = layer.details || {}
      vt_malicious = details.dig("virustotal_malicious_count").to_i
      uh_malicious = details.dig("urlhaus_malicious_count").to_i
      total_malicious = vt_malicious + uh_malicious

      if total_malicious > 0
        finding
      else
        Rails.logger.warn("LlmFindingValidator: HALLUCINATION stripped — URL malicious claim with 0 detections: #{finding}")
        nil
      end
    end

    def validate_attachment_claim(finding)
      layer = @layers["external_api"]

      unless layer
        Rails.logger.warn("LlmFindingValidator: Attachment claim without external_api layer: #{finding}")
        return "[Não verificado] #{finding}"
      end

      details = layer.details || {}
      attachments_malicious = details.dig("attachments_malicious_count").to_i

      if attachments_malicious > 0
        finding
      else
        Rails.logger.warn("LlmFindingValidator: HALLUCINATION stripped — attachment claim with 0 detections: #{finding}")
        nil
      end
    end
  end
end
