module Analysis
  class HeaderAuthAnalyzer
    LAYER_NAME = "header_auth"
    WEIGHT = AnalysisLayer::WEIGHTS[LAYER_NAME]

    SUSPICIOUS_MAILERS = %w[
      PHPMailer swiftmailer sendblaster
      massmail bulkmail atompark
    ].freeze

    def initialize(email)
      @email = email
      @findings = []
      @score = 0
      @details = {}
    end

    def analyze
      parse_authentication_results
      check_spf
      check_dkim
      check_dmarc
      check_arc
      check_reply_to_mismatch
      check_antispam_headers
      check_x_mailer
      check_received_chain
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

    def headers
      @headers ||= @email.raw_headers.to_s
    end

    def parse_authentication_results
      auth_results = headers.scan(/Authentication-Results:.*?(?=\n\S|\z)/m)
      @details[:authentication_results_count] = auth_results.size
      @details[:raw_auth_results] = auth_results.map(&:strip).first(3)
    end

    def check_spf
      spf_match = headers.match(/spf=(pass|fail|softfail|neutral|none|temperror|permerror)/i)
      result = spf_match ? spf_match[1].downcase : "missing"
      @details[:spf] = result

      case result
      when "pass"
        # Good
      when "fail"
        @findings << "SPF authentication failed — sender IP not authorized"
        @score += 30
      when "softfail"
        @findings << "SPF softfail — sender IP not explicitly authorized"
        @score += 15
      when "none", "missing"
        @findings << "No SPF record found for sender domain"
        @score += 10
      when "neutral"
        @score += 5
      end
    end

    def check_dkim
      dkim_match = headers.match(/dkim=(pass|fail|none|neutral|temperror|permerror)/i)
      result = dkim_match ? dkim_match[1].downcase : "missing"
      @details[:dkim] = result

      case result
      when "pass"
        # Good
      when "fail"
        @findings << "DKIM signature verification failed"
        @score += 25
      when "none", "missing"
        @findings << "No DKIM signature present"
        @score += 10
      end
    end

    def check_dmarc
      dmarc_match = headers.match(/dmarc=(pass|fail|none|bestguesspass)/i)
      result = dmarc_match ? dmarc_match[1].downcase : "missing"
      @details[:dmarc] = result

      # Check DMARC policy
      policy_match = headers.match(/dmarc=\w+\s*\(p=(\w+)/i)
      @details[:dmarc_policy] = policy_match ? policy_match[1].downcase : nil

      case result
      when "pass"
        # Good
      when "fail"
        @findings << "DMARC authentication failed"
        @score += 25
      when "none", "missing"
        @findings << "No DMARC policy found"
        @score += 10
      when "bestguesspass"
        @findings << "DMARC best-guess pass (no policy published)"
        @score += 5
      end
    end

    def check_arc
      arc_match = headers.match(/arc=(pass|fail|none)/i)
      result = arc_match ? arc_match[1].downcase : "missing"
      @details[:arc] = result
    end

    def check_reply_to_mismatch
      from = @email.from_address&.downcase
      reply_to = @email.reply_to_address&.downcase
      return unless from && reply_to

      from_domain = from.split("@").last
      reply_domain = reply_to.split("@").last

      if from_domain != reply_domain
        @findings << "Reply-To domain (#{reply_domain}) differs from From domain (#{from_domain})"
        @score += 20
        @details[:reply_to_mismatch] = true
      else
        @details[:reply_to_mismatch] = false
      end
    end

    def check_antispam_headers
      # Microsoft SCL (Spam Confidence Level)
      scl_match = headers.match(/SCL:(\d+)/i)
      if scl_match
        scl = scl_match[1].to_i
        @details[:scl] = scl
        if scl >= 5
          @findings << "Microsoft Spam Confidence Level is high (#{scl})"
          @score += [scl * 3, 25].min
        end
      end

      # X-Spam headers
      spam_status = headers.match(/X-Spam-Status:\s*(Yes|No)/i)
      if spam_status&.captures&.first&.downcase == "yes"
        @findings << "Flagged as spam by upstream filter"
        @score += 15
        @details[:upstream_spam_flag] = true
      end
    end

    def check_x_mailer
      mailer_match = headers.match(/X-Mailer:\s*(.+)/i)
      return unless mailer_match

      mailer = mailer_match[1].strip.downcase
      @details[:x_mailer] = mailer_match[1].strip

      if SUSPICIOUS_MAILERS.any? { |s| mailer.include?(s) }
        @findings << "Suspicious mail client: #{mailer_match[1].strip}"
        @score += 15
      end
    end

    def check_received_chain
      received_headers = headers.scan(/Received:\s*from\s+(\S+)/i).flatten
      @details[:received_chain_length] = received_headers.size
      @details[:received_hosts] = received_headers.first(5)

      # Check for suspicious sender IP in last Received header
      ip_match = headers.match(/Received:.*?from.*?\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]/m)
      if ip_match
        @details[:sender_ip] = ip_match[1]
      end
    end

    def calculate_score
      @score = [@score, 100].min
    end

    def calculate_confidence
      # Higher confidence when we have more auth data
      auth_signals = [:spf, :dkim, :dmarc].count { |k| @details[k] && @details[k] != "missing" }
      base = 0.5 + (auth_signals * 0.15)
      [base, 1.0].min
    end

    def build_explanation
      if @findings.empty?
        "Email authentication checks all passed. SPF: #{@details[:spf]}, DKIM: #{@details[:dkim]}, DMARC: #{@details[:dmarc]}."
      else
        "Found #{@findings.size} issue(s): #{@findings.join('; ')}."
      end
    end
  end
end
