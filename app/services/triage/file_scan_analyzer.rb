require "digest"

module Triage
  class FileScanAnalyzer
    LAYER_NAME = "triage_file_scan"
    WEIGHT = AnalysisLayer::WEIGHTS[LAYER_NAME]
    MAX_ATTACHMENTS = 10

    DANGEROUS_EXTENSIONS = %w[exe bat cmd com scr pif vbs js wsf hta msi dll ps1 jar apk ipa].freeze

    def initialize(email)
      @email = email
      @findings = []
      @score = 0
      @details = { attachments: [] }
    end

    def analyze
      attachments = collect_attachments
      scan_attachments(attachments) if attachments.any?
      check_dangerous_extensions(attachments) if attachments.any?
      calculate_score

      layer = @email.analysis_layers.find_or_initialize_by(layer_name: LAYER_NAME)
      layer.update!(
        score: @score,
        weight: WEIGHT,
        confidence: calculate_confidence(attachments),
        details: @details,
        explanation: build_explanation(attachments),
        status: "completed"
      )

      layer
    end

    private

    def collect_attachments
      parsed = Array(@email.attachments_info)
      return parsed.first(MAX_ATTACHMENTS) if parsed.any?
      return [] unless @email.raw_source.present?

      Mail.new(@email.raw_source).attachments.first(MAX_ATTACHMENTS).map do |attachment|
        decoded = attachment.body.decoded
        {
          "filename" => attachment.filename,
          "content_type" => attachment.content_type,
          "size" => decoded.bytesize,
          "sha256" => Digest::SHA256.hexdigest(decoded)
        }
      end
    rescue
      []
    end

    def scan_attachments(attachments)
      client = VirusTotalClient.new
      malicious_count = 0

      attachments.each do |attachment|
        sha256 = attachment["sha256"] || attachment[:sha256]
        next if sha256.blank?

        result = client.scan_file_hash(sha256)

        att_result = {
          filename: attachment["filename"] || attachment[:filename],
          content_type: attachment["content_type"] || attachment[:content_type],
          sha256: sha256,
          malicious: result&.dig(:malicious) || false,
          detection_count: result&.dig(:detection_count)
        }
        @details[:attachments] << att_result

        if result&.dig(:malicious)
          malicious_count += 1
          @findings << "Arquivo malicioso: #{att_result[:filename]} (#{result[:detection_count]} detecções)"
        end
      end

      if malicious_count > 0
        @score += [malicious_count * 30, 80].min
      end

      @details[:attachments_scanned] = @details[:attachments].size
      @details[:attachments_malicious_count] = malicious_count
    end

    def check_dangerous_extensions(attachments)
      attachments.each do |attachment|
        filename = (attachment["filename"] || attachment[:filename]).to_s
        ext = File.extname(filename).delete_prefix(".").downcase
        if DANGEROUS_EXTENSIONS.include?(ext)
          @findings << "Anexo com extensão perigosa: #{filename}"
          @score += 25
        end
      end
    end

    def calculate_score
      @score = [@score, 100].min
    end

    def calculate_confidence(attachments)
      if attachments.empty?
        0.3
      elsif @details[:attachments].size > 0
        0.9
      else
        0.5
      end
    end

    def build_explanation(attachments)
      if attachments.empty?
        "Nenhum anexo encontrado na mensagem."
      elsif @findings.empty?
        "Verificou #{@details[:attachments].size} anexo(s) — nenhuma ameaça detectada."
      else
        "Encontrada(s) #{@findings.size} ameaça(s): #{@findings.join('; ')}."
      end
    end
  end
end
