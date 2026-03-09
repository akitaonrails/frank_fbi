module Triage
  class RiskEscalationPolicy
    def initialize(layers)
      @layers = layers.index_by(&:layer_name)
    end

    def evaluate
      escalations = []

      collect_urlhaus_escalations(escalations)
      collect_virustotal_escalations(escalations)
      collect_file_escalations(escalations)

      {
        floor: escalations.map { |e| e[:floor] }.max.to_i,
        reasons: escalations.sort_by { |e| -e[:floor] }.map { |e| e[:reason] }
      }
    end

    private

    def collect_urlhaus_escalations(escalations)
      layer = @layers["triage_url_scan"]
      return unless layer&.details.is_a?(Hash)

      if detail_value(layer, :urlhaus_malicious_count).to_i.positive?
        escalations << {
          floor: 100,
          reason: "URLhaus confirmou URL maliciosa."
        }
      end
    end

    def collect_virustotal_escalations(escalations)
      layer = @layers["triage_url_scan"]
      return unless layer&.details.is_a?(Hash)

      Array(detail_value(layer, :virustotal)).each do |url_result|
        detections = numeric_value(url_result, :detections)
        next if detections.zero?

        floor = detections >= 5 ? 100 : 95
        escalations << {
          floor: floor,
          reason: "URL sinalizada pelo VirusTotal (#{detections} detecções)."
        }
      end
    end

    def collect_file_escalations(escalations)
      layer = @layers["triage_file_scan"]
      return unless layer&.details.is_a?(Hash)

      Array(detail_value(layer, :attachments)).each do |att|
        detections = numeric_value(att, :detection_count)
        next if detections.zero?

        floor = detections >= 5 ? 100 : 95
        escalations << {
          floor: floor,
          reason: "Arquivo sinalizado pelo VirusTotal (#{detections} detecções)."
        }
      end
    end

    def detail_value(layer, key)
      return nil unless layer.details.is_a?(Hash)
      layer.details[key.to_s] || layer.details[key.to_sym]
    end

    def numeric_value(hash, key)
      value = hash[key.to_s] || hash[key.to_sym]
      value.to_i
    end
  end
end
