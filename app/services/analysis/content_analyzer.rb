require "uri"

module Analysis
  class ContentAnalyzer
    LAYER_NAME = "content_analysis"
    WEIGHT = AnalysisLayer::WEIGHTS[LAYER_NAME]

    URL_SHORTENERS = %w[
      bit.ly tinyurl.com goo.gl ow.ly t.co is.gd
      buff.ly adf.ly rb.gy short.link cutt.ly
      tiny.cc s.id rebrand.ly bl.ink
    ].freeze

    DANGEROUS_EXTENSIONS = %w[
      .exe .scr .bat .cmd .com .pif .vbs .js .wsf
      .msi .dll .jar .ps1 .reg .inf .hta .cpl
    ].freeze

    URGENCY_PATTERNS = [
      /\b(urgent|immediately|right\s+now|act\s+now|don'?t\s+delay)\b/i,
      /\b(expires?\s+(today|soon|in\s+\d+)|limited\s+time|last\s+chance)\b/i,
      /\b(suspend|deactivat|terminat|block|restrict)\w*\s+(your|the)\s+(account|access)/i,
      /\b(verify|confirm|validate)\s+your\s+(identity|account|information|details)/i,
      /\b(within\s+\d+\s+hours?|within\s+24|48\s+hours?)\b/i
    ].freeze

    FINANCIAL_PATTERNS = [
      /\b(wire\s+transfer|western\s+union|money\s+gram|bitcoin|cryptocurrency)\b/i,
      /\b(bank\s+account|routing\s+number|swift\s+code|iban)\b/i,
      /\b(lottery|won|winner|prize|inheritance|million\s+dollars?)\b/i,
      /\b(investment\s+opportunity|guaranteed\s+returns?|risk.?free)\b/i,
      /\b(atm\s+card|compensation\s+payment|unclaimed\s+funds?)\b/i,
      /\$\s*\d{1,3}(?:,\d{3})*(?:\.\d{2})?\s*(?:million|billion|USD)/i
    ].freeze

    PII_REQUEST_PATTERNS = [
      /\b(social\s+security|ssn|passport\s+number)\b/i,
      /\b(credit\s+card|debit\s+card|card\s+number|cvv|cvc)\b/i,
      /\b(password|login\s+credentials?|pin\s+number)\b/i,
      /\b(date\s+of\s+birth|mother'?s?\s+maiden)\b/i,
      /\b(send\s+(me|us)\s+your\s+(id|identification|photo))\b/i
    ].freeze

    AUTHORITY_IMPERSONATION = [
      /\b(FBI|CIA|NSA|IRS|Federal\s+Bureau)\b/,
      /\b(United\s+Nations|UN\s+Office|World\s+Bank|IMF)\b/i,
      /\b(Department\s+of\s+(State|Treasury|Justice|Homeland))\b/i,
      /\b(Interpol|Scotland\s+Yard|Secret\s+Service)\b/i,
      /\b(diplomat|ambassador|minister|secretary\s+general)\b/i,
      /\b(barrister|attorney\s+general|high\s+court)\b/i
    ].freeze

    PHISHING_PHRASES = [
      /\bclick\s+(here|below|the\s+link)\s+to\s+(verify|confirm|update|secure)/i,
      /\byour\s+account\s+(has\s+been|will\s+be|is)\s+(compromised|suspended|locked)/i,
      /\bunusual\s+(activity|sign.?in|login)\s+(detected|found|noticed)/i,
      /\bsecure\s+your\s+account\b/i,
      /\bfailure\s+to\s+(comply|respond|verify)\b/i
    ].freeze

    def initialize(email)
      @email = email
      @findings = []
      @score = 0
      @details = {}
    end

    def analyze
      text = combined_text

      analyze_urls
      analyze_url_mismatches
      detect_url_shorteners
      analyze_patterns(text)
      analyze_attachments
      check_grammar_flags(text)
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

    def combined_text
      [@email.body_text, @email.subject].compact.join(" ")
    end

    def analyze_urls
      urls = @email.extracted_urls || []
      @details[:url_count] = urls.size
      @details[:urls] = urls.first(20)

      # Extract unique domains from URLs
      domains = urls.filter_map { |u| URI.parse(u).host rescue nil }.uniq
      @details[:url_domains] = domains

      if urls.size > 10
        @findings << "Contains an unusually high number of URLs (#{urls.size})"
        @score += 5
      end
    end

    def analyze_url_mismatches
      html = @email.body_html.to_s
      mismatches = []

      # Find <a> tags where display text looks like a URL but href is different
      html.scan(/<a[^>]+href=["']([^"']+)["'][^>]*>(.*?)<\/a>/im).each do |href, text|
        display_text = text.gsub(/<[^>]+>/, "").strip
        next unless display_text.match?(%r{https?://})

        begin
          href_host = URI.parse(href).host&.downcase
          text_host = URI.parse(display_text).host&.downcase
          if href_host && text_host && href_host != text_host
            mismatches << { display: display_text, actual: href }
          end
        rescue URI::InvalidURIError
          next
        end
      end

      if mismatches.any?
        @findings << "Found #{mismatches.size} URL display/href mismatch(es) — classic phishing technique"
        @score += mismatches.size * 15
        @details[:url_mismatches] = mismatches.first(5)
      end
    end

    def detect_url_shorteners
      urls = @email.extracted_urls || []
      shortened = urls.select do |url|
        host = URI.parse(url).host&.downcase rescue nil
        host && URL_SHORTENERS.include?(host)
      end

      if shortened.any?
        @findings << "Contains #{shortened.size} shortened URL(s) that hide the real destination"
        @score += shortened.size * 8
        @details[:shortened_urls] = shortened
      end
    end

    def analyze_patterns(text)
      check_pattern_group(text, URGENCY_PATTERNS, "urgency", "Urgency/pressure language detected", 8)
      check_pattern_group(text, FINANCIAL_PATTERNS, "financial", "Financial fraud indicators detected", 12)
      check_pattern_group(text, PII_REQUEST_PATTERNS, "pii_request", "Requests for personal/sensitive information", 15)
      check_pattern_group(text, AUTHORITY_IMPERSONATION, "authority", "Impersonation of authority/government detected", 12)
      check_pattern_group(text, PHISHING_PHRASES, "phishing", "Phishing language patterns detected", 10)
    end

    def check_pattern_group(text, patterns, key, finding_message, score_per_match)
      matches = patterns.count { |p| text.match?(p) }
      @details[:"#{key}_matches"] = matches

      if matches > 0
        @findings << "#{finding_message} (#{matches} pattern(s))"
        @score += [matches * score_per_match, 30].min
      end
    end

    def analyze_attachments
      attachments = @email.attachments_info || []
      @details[:attachment_count] = attachments.size

      dangerous = attachments.select do |att|
        filename = att["filename"].to_s.downcase
        DANGEROUS_EXTENSIONS.any? { |ext| filename.end_with?(ext) }
      end

      if dangerous.any?
        names = dangerous.map { |a| a["filename"] }
        @findings << "Dangerous attachment type(s): #{names.join(', ')}"
        @score += 25
        @details[:dangerous_attachments] = names
      end

      # Check for double extensions (e.g., invoice.pdf.exe)
      double_ext = attachments.select do |att|
        att["filename"].to_s.match?(/\.\w+\.\w+$/)
      end
      if double_ext.any?
        @findings << "Attachment(s) with double extension (possible disguise)"
        @score += 15
      end
    end

    def check_grammar_flags(text)
      # Check for ALL CAPS subject
      subject = @email.subject.to_s
      if subject.length > 10 && subject == subject.upcase && subject.match?(/[A-Z]/)
        @findings << "Subject line is entirely in ALL CAPS"
        @score += 8
        @details[:all_caps_subject] = true
      end

      # Check for excessive exclamation/question marks
      if subject.count("!") >= 3 || text.scan(/!{2,}/).any?
        @findings << "Excessive exclamation marks in email"
        @score += 5
        @details[:excessive_punctuation] = true
      end
    end

    def calculate_score
      @score = [@score, 100].min
    end

    def calculate_confidence
      text_length = combined_text.length
      if text_length > 200
        1.0
      elsif text_length > 50
        0.8
      else
        0.5
      end
    end

    def build_explanation
      if @findings.empty?
        "No suspicious content patterns detected. #{@details[:url_count]} URL(s) found, #{@details[:attachment_count]} attachment(s)."
      else
        "Found #{@findings.size} concern(s): #{@findings.join('; ')}."
      end
    end
  end
end
