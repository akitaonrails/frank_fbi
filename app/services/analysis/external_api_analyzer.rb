module Analysis
  class ExternalApiAnalyzer
    LAYER_NAME = "external_api"
    WEIGHT = AnalysisLayer::WEIGHTS[LAYER_NAME]
    MAX_URLS_TO_SCAN = 10

    def initialize(email)
      @email = email
      @findings = []
      @score = 0
      @details = { virustotal: [], urlhaus: [] }
    end

    def analyze
      urls = (@email.extracted_urls || []).first(MAX_URLS_TO_SCAN)

      if urls.empty?
        return build_no_urls_result
      end

      scan_with_urlhaus(urls)
      scan_with_virustotal(urls)
      check_domain_in_urlhaus
      calculate_score

      layer = @email.analysis_layers.find_or_initialize_by(layer_name: LAYER_NAME)
      layer.update!(
        score: @score,
        weight: WEIGHT,
        confidence: calculate_confidence,
        details: @details,
        explanation: build_explanation,
        status: "completed"
      )

      layer
    end

    private

    def scan_with_urlhaus(urls)
      client = UrlhausClient.new
      malicious_count = 0

      urls.each do |url|
        result = client.scan_url(url)
        next unless result

        @details[:urlhaus] << { url: url, malicious: result[:malicious], threat: result[:threat_type] }
        malicious_count += 1 if result[:malicious]
      end

      if malicious_count > 0
        @findings << "#{malicious_count} URL(s) flagged as malicious by URLhaus"
        @score += [malicious_count * 20, 50].min
      end

      @details[:urlhaus_malicious_count] = malicious_count
    end

    def scan_with_virustotal(urls)
      client = VirusTotalClient.new
      malicious_count = 0

      urls.first(4).each do |url| # VirusTotal rate limit: 4/min
        result = client.scan_url(url)
        next unless result

        @details[:virustotal] << {
          url: url,
          malicious: result[:malicious],
          detections: result[:detection_count]
        }
        malicious_count += 1 if result[:malicious]
      end

      if malicious_count > 0
        @findings << "#{malicious_count} URL(s) flagged by VirusTotal"
        @score += [malicious_count * 15, 40].min
      end

      @details[:virustotal_malicious_count] = malicious_count
    end

    def check_domain_in_urlhaus
      return unless @email.sender_domain

      client = UrlhausClient.new
      result = client.scan_domain(@email.sender_domain)
      return unless result

      @details[:domain_urlhaus] = result
      if result[:malicious]
        @findings << "Sender domain #{@email.sender_domain} is listed in URLhaus malware database"
        @score += 25
      end
    end

    def calculate_score
      @score = [@score, 100].min
    end

    def calculate_confidence
      scanned = @details[:virustotal].size + @details[:urlhaus].size
      if scanned > 5
        1.0
      elsif scanned > 0
        0.8
      else
        0.4
      end
    end

    def build_explanation
      if @findings.empty?
        urls_count = (@email.extracted_urls || []).size
        "Scanned #{[@details[:urlhaus].size, @details[:virustotal].size].max} of #{urls_count} URL(s) — no threats detected."
      else
        "Found #{@findings.size} threat(s): #{@findings.join('; ')}."
      end
    end

    def build_no_urls_result
      layer = @email.analysis_layers.find_or_initialize_by(layer_name: LAYER_NAME)
      layer.update!(
        score: 0,
        weight: WEIGHT,
        confidence: 0.3,
        details: { note: "No URLs to scan" },
        explanation: "No URLs found in email body to scan against threat databases.",
        status: "completed"
      )
      layer
    end
  end
end
