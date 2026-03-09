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
      if dangerous.any?
        escalations << {
          floor: 80,
          reason: "E-mail contém anexo executável ou claramente perigoso."
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
      content = @layers["content_analysis"]
      return unless header && content

      reply_to_mismatch = truthy?(header.details || {}, :reply_to_mismatch)
      if reply_to_mismatch && header.score.to_i >= 20 && content.score.to_i >= 45
        escalations << {
          floor: 65,
          reason: "Reply-To divergente combinado com conteúdo fortemente suspeito."
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
