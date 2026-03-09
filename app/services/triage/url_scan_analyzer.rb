require "digest"

module Triage
  class UrlScanAnalyzer
    LAYER_NAME = "triage_url_scan"
    WEIGHT = AnalysisLayer::WEIGHTS[LAYER_NAME]
    MAX_URLS = 25

    def initialize(email)
      @email = email
      @findings = []
      @score = 0
      @details = { virustotal: [], urlhaus: [], url_domains: [] }
    end

    def analyze
      urls = (@email.extracted_urls || []).first(MAX_URLS)

      scan_with_urlhaus(urls) if urls.any?
      scan_with_virustotal(urls) if urls.any?
      check_url_domains(urls) if urls.any?
      calculate_score

      layer = @email.analysis_layers.find_or_initialize_by(layer_name: LAYER_NAME)
      layer.update!(
        score: @score,
        weight: WEIGHT,
        confidence: calculate_confidence(urls),
        details: @details,
        explanation: build_explanation(urls),
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
        @findings << "#{malicious_count} URL(s) marcada(s) como maliciosa(s) pelo URLhaus"
        @score += [malicious_count * 25, 60].min
      end

      @details[:urlhaus_malicious_count] = malicious_count
    end

    def scan_with_virustotal(urls)
      client = VirusTotalClient.new
      malicious_count = 0

      urls.each do |url|
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
        @findings << "#{malicious_count} URL(s) sinalizada(s) pelo VirusTotal"
        @score += [malicious_count * 20, 50].min
      end

      @details[:virustotal_malicious_count] = malicious_count
    end

    def check_url_domains(urls)
      domains = urls.filter_map { |url| URI.parse(url).host rescue nil }.uniq

      domains.first(10).each do |domain|
        domain_result = { domain: domain, young: false, blacklisted: false }

        whois = WhoisLookupService.new(domain).lookup
        if whois
          age = whois[:domain_age_days]
          if age && age < 30
            @findings << "Domínio #{domain} tem apenas #{age} dias"
            @score += 20
            domain_result[:young] = true
            domain_result[:age_days] = age
          elsif age && age < 90
            @findings << "Domínio #{domain} tem apenas #{age} dias"
            @score += 10
            domain_result[:young] = true
            domain_result[:age_days] = age
          end
        end

        bl_results = DnsBlacklistChecker.new(domain).check
        if bl_results.present?
          hits = bl_results.values.count { |r| r[:listed] }
          if hits > 0
            @findings << "Domínio #{domain} listado em #{hits} lista(s) negra(s)"
            @score += [hits * 15, 30].min
            domain_result[:blacklisted] = true
            domain_result[:blacklist_hits] = hits
          end
        end

        @details[:url_domains] << domain_result
      end
    end

    def calculate_score
      @score = [@score, 100].min
    end

    def calculate_confidence(urls)
      total_signals = @details[:virustotal].size + @details[:urlhaus].size + @details[:url_domains].size

      if urls.empty?
        0.3
      elsif total_signals > 8
        1.0
      elsif total_signals > 4
        0.9
      elsif total_signals > 0
        0.8
      else
        0.4
      end
    end

    def build_explanation(urls)
      if @findings.empty?
        if urls.empty?
          "Nenhuma URL encontrada na mensagem."
        else
          scanned = [@details[:urlhaus].size, @details[:virustotal].size].max
          "Verificou #{scanned} de #{urls.size} URL(s) — nenhuma ameaça detectada."
        end
      else
        "Encontrada(s) #{@findings.size} ameaça(s): #{@findings.join('; ')}."
      end
    end
  end
end
