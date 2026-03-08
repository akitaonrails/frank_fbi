require "digest"

module Analysis
  class ExternalApiAnalyzer
    LAYER_NAME = "external_api"
    WEIGHT = AnalysisLayer::WEIGHTS[LAYER_NAME]
    MAX_URLS_TO_SCAN = 10
    MAX_DOMAINS_TO_CHECK = 5
    MAX_ATTACHMENTS_TO_SCAN = 4
    IMAGE_EXTENSIONS = %w[jpg jpeg png gif bmp webp svg ico].freeze
    IMAGE_CONTENT_TYPES = %w[image/jpeg image/png image/gif image/bmp image/webp image/svg+xml image/x-icon].freeze

    def initialize(email)
      @email = email
      @findings = []
      @score = 0
      @details = { virustotal: [], urlhaus: [], url_domains: [], attachments: [] }
    end

    def analyze
      urls = (@email.extracted_urls || []).first(MAX_URLS_TO_SCAN)

      scan_with_urlhaus(urls) if urls.any?
      scan_with_virustotal(urls) if urls.any?
      check_domain_in_urlhaus
      check_url_domains(urls)
      scan_attachments
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

    def check_url_domains(urls)
      domains = extract_unique_domains(urls)
      return if domains.empty?

      domains.first(MAX_DOMAINS_TO_CHECK).each do |domain|
        domain_result = { domain: domain, whois: nil, blacklisted: false, young: false }

        whois = WhoisLookupService.new(domain).lookup
        if whois
          age = whois[:domain_age_days]
          if age && age < 30
            @findings << "URL domain #{domain} is only #{age} days old"
            @score += 20
            domain_result[:young] = true
            domain_result[:age_days] = age
          elsif age && age < 90
            @findings << "URL domain #{domain} is only #{age} days old"
            @score += 10
            domain_result[:young] = true
            domain_result[:age_days] = age
          end
          domain_result[:whois] = { age_days: age, created: whois[:created_date] }
        end

        bl_results = DnsBlacklistChecker.new(domain).check
        if bl_results.present?
          hits = bl_results.values.count { |r| r[:listed] }
          if hits > 0
            bl_score = [hits * 15, 30].min
            @findings << "URL domain #{domain} listed on #{hits} blacklist(s)"
            @score += bl_score
            domain_result[:blacklisted] = true
            domain_result[:blacklist_hits] = hits
          end
        end

        @details[:url_domains] << domain_result
      end
    end

    def scan_attachments
      return unless @email.raw_source.present?

      mail = Mail.new(@email.raw_source)
      non_image_attachments = mail.attachments.reject { |att| image_attachment?(att) }
      return if non_image_attachments.empty?

      client = VirusTotalClient.new
      malicious_count = 0

      non_image_attachments.first(MAX_ATTACHMENTS_TO_SCAN).each do |attachment|
        sha256 = Digest::SHA256.hexdigest(attachment.body.decoded)
        result = client.scan_file_hash(sha256)

        att_result = {
          filename: attachment.filename,
          content_type: attachment.content_type,
          sha256: sha256,
          malicious: result&.dig(:malicious) || false,
          detection_count: result&.dig(:detection_count)
        }
        @details[:attachments] << att_result

        if result&.dig(:malicious)
          malicious_count += 1
          break if malicious_count >= 2 # cap at +50
        end
      end

      if malicious_count > 0
        @findings << "#{malicious_count} attachment(s) flagged as malicious by VirusTotal"
        @score += [malicious_count * 25, 50].min
      end

      @details[:attachments_scanned] = @details[:attachments].size
      @details[:attachments_malicious_count] = malicious_count
    end

    def calculate_score
      @score = [@score, 100].min
    end

    def calculate_confidence
      url_signals = @details[:virustotal].size + @details[:urlhaus].size
      domain_signals = @details[:url_domains].size
      attachment_signals = @details[:attachments].size
      total_signals = url_signals + domain_signals + attachment_signals

      if total_signals > 8
        1.0
      elsif total_signals > 4
        0.9
      elsif total_signals > 0
        0.8
      else
        0.4
      end
    end

    def build_explanation
      if @findings.empty?
        parts = []
        urls_count = (@email.extracted_urls || []).size
        scanned = [@details[:urlhaus].size, @details[:virustotal].size].max
        parts << "Scanned #{scanned} of #{urls_count} URL(s)" if urls_count > 0
        parts << "checked #{@details[:url_domains].size} URL domain(s)" if @details[:url_domains].any?
        parts << "scanned #{@details[:attachments].size} attachment(s)" if @details[:attachments].any?

        if parts.empty?
          "No URLs or attachments to scan against threat databases."
        else
          "#{parts.join(', ')} — no threats detected."
        end
      else
        "Found #{@findings.size} threat(s): #{@findings.join('; ')}."
      end
    end

    def extract_unique_domains(urls)
      domains = urls.filter_map { |url| URI.parse(url).host rescue nil }.uniq
      # Exclude the sender's own domain — already checked by Layer 2
      domains.reject { |d| d == @email.sender_domain }
    end

    def image_attachment?(attachment)
      ext = File.extname(attachment.filename.to_s).delete_prefix(".").downcase
      return true if IMAGE_EXTENSIONS.include?(ext)

      content_type = attachment.content_type.to_s.split(";").first.to_s.strip.downcase
      IMAGE_CONTENT_TYPES.include?(content_type)
    end
  end
end
