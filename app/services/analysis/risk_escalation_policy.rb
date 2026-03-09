module Analysis
  class RiskEscalationPolicy
    def initialize(layers)
      @layers = index_layers(layers)
    end

    def evaluate
      escalations = []

      collect_blacklist_escalations(escalations)
      collect_external_api_escalations(escalations)
      collect_content_escalations(escalations)
      collect_combination_escalations(escalations)
      collect_llm_escalations(escalations)

      {
        floor: escalations.map { |entry| entry[:floor] }.max.to_i,
        reasons: escalations.sort_by { |entry| -entry[:floor] }.map { |entry| entry[:reason] }
      }
    end

    private

    def index_layers(layers)
      layers.index_by(&:layer_name)
    end

    def collect_blacklist_escalations(escalations)
      layer = @layers["sender_reputation"]
      return unless layer

      blacklist_results = detail_value(layer, :blacklist_results).to_h
      blacklist_results.each_value do |entry|
        value = entry.is_a?(Hash) ? entry : {}
        next unless truthy?(value, :authoritative_malicious)

        categories = Array(value["categories"] || value[:categories]).join(", ")
        escalations << {
          floor: 100,
          reason: "Remetente listado em blacklist autoritativa (#{categories.presence || 'categoria confirmada'})."
        }
      end
    end

    def collect_external_api_escalations(escalations)
      layer = @layers["external_api"]
      return unless layer

      if detail_value(layer, :urlhaus_malicious_count).to_i.positive?
        escalations << {
          floor: 100,
          reason: "URLhaus confirmou URL maliciosa."
        }
      end

      if truthy?(detail_value(layer, :domain_urlhaus).to_h, :malicious)
        escalations << {
          floor: 100,
          reason: "URLhaus confirmou domínio do remetente ligado a malware."
        }
      end

      Array(detail_value(layer, :attachments)).each do |attachment|
        detections = numeric_value(attachment, :detection_count)
        next if detections.zero?

        floor =
          if detections >= 8
            100
          elsif detections >= 3
            95
          else
            85
          end

        escalations << {
          floor: floor,
          reason: "Anexo sinalizado pelo VirusTotal (#{detections} detecções)."
        }
      end

      Array(detail_value(layer, :virustotal)).each do |url_result|
        detections = numeric_value(url_result, :detections)
        next if detections.zero?

        floor =
          if detections >= 8
            95
          elsif detections >= 3
            90
          else
            75
          end

        escalations << {
          floor: floor,
          reason: "URL sinalizada pelo VirusTotal (#{detections} detecções)."
        }
      end
    end

    def collect_content_escalations(escalations)
      layer = @layers["content_analysis"]
      return unless layer

      dangerous = Array(detail_value(layer, :dangerous_attachments))
      suspicious = Array(detail_value(layer, :suspicious_attachments))
      double_extensions = Array(detail_value(layer, :double_extension_attachments))

      if dangerous.any?
        escalations << {
          floor: 80,
          reason: "E-mail contém anexo executável ou claramente perigoso."
        }
      end

      if double_extensions.any?
        escalations << {
          floor: 75,
          reason: "E-mail contém anexo com extensão dupla, padrão comum de disfarce."
        }
      end

      if suspicious.any?
        categories = suspicious.filter_map do |entry|
          value = entry.is_a?(Hash) ? (entry["category"] || entry[:category]) : nil
          value&.tr("_", " ")
        end.uniq

        escalations << {
          floor: suspicious.size >= 2 ? 65 : 55,
          reason: "E-mail contém anexo altamente suspeito#{categories.any? ? " (#{categories.join(', ')})" : ''}."
        }
      end

      mismatches = Array(detail_value(layer, :url_mismatches))
      if mismatches.any?
        escalations << {
          floor: 70,
          reason: "E-mail contém divergência entre texto do link e destino real."
        }
      end
    end

    def collect_combination_escalations(escalations)
      header = @layers["header_auth"]
      llm = @layers["llm_analysis"]
      return unless header

      reply_to_mismatch = truthy?(header.details || {}, :reply_to_mismatch)
      return unless reply_to_mismatch && header.score.to_i >= 20

      # Check LLM content_patterns for dangerous combinations
      if llm&.details.is_a?(Hash)
        patterns = (llm.details["content_patterns"] || llm.details[:content_patterns]).to_h
        authority = patterns["authority_impersonation"].to_i + patterns[:authority_impersonation].to_i
        pii = patterns["pii_request"].to_i + patterns[:pii_request].to_i
        phishing = patterns["phishing"].to_i + patterns[:phishing].to_i
        total_dangerous = authority + pii + phishing

        if total_dangerous >= 2
          escalations << {
            floor: 65,
            reason: "Reply-To divergente combinado com padrões perigosos detectados pela IA (autoridade/PII/phishing)."
          }
        end
      end

      # Fallback: if LLM layer not available, use content score
      content = @layers["content_analysis"]
      if llm.nil? && content && content.score.to_i >= 30
        escalations << {
          floor: 65,
          reason: "Reply-To divergente combinado com conteúdo estruturalmente suspeito."
        }
      end
    end

    def collect_llm_escalations(escalations)
      layer = @layers["llm_analysis"]
      return unless layer
      return unless layer.confidence.to_f >= 0.5

      if layer.score.to_i >= 70
        escalations << {
          floor: 60,
          reason: "Análise por IA identificou forte indicação de fraude (score #{layer.score}, confiança #{(layer.confidence * 100).round}%)."
        }
      elsif layer.score.to_i >= 55
        escalations << {
          floor: 45,
          reason: "Análise por IA identificou indicadores suspeitos (score #{layer.score}, confiança #{(layer.confidence * 100).round}%)."
        }
      end
    end

    def detail_value(layer, key)
      return nil unless layer.details.is_a?(Hash)

      layer.details[key.to_s] || layer.details[key.to_sym]
    end

    def truthy?(hash, key)
      hash[key.to_s] || hash[key.to_sym]
    end

    def numeric_value(hash, key)
      value = hash[key.to_s] || hash[key.to_sym]
      value.to_i
    end
  end
end
