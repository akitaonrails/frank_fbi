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
      if indirect_sender_context?
        return build_indeterminate_result
      end

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

    def outer_from_address
      @outer_from_address ||= begin
        match = headers.match(/^From:\s*(?:.+<)?([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})>?/i)
        match ? match[1].downcase.strip : nil
      end
    end

    def indirect_sender_context?
      return false if outer_from_address.blank? || @email.from_address.blank?

      outer_from_address != @email.from_address.downcase
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
        @findings << "Autenticação SPF falhou — IP do remetente não autorizado"
        @score += 30
      when "softfail"
        @findings << "SPF softfail — IP do remetente não explicitamente autorizado"
        @score += 15
      when "none", "missing"
        @findings << "Nenhum registro SPF encontrado para o domínio do remetente"
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
        @findings << "Verificação da assinatura DKIM falhou"
        @score += 25
      when "none", "missing"
        @findings << "Nenhuma assinatura DKIM presente"
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
        @findings << "Autenticação DMARC falhou"
        @score += 25
      when "none", "missing"
        @findings << "Nenhuma política DMARC encontrada"
        @score += 10
      when "bestguesspass"
        @findings << "DMARC best-guess pass (nenhuma política publicada)"
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
        @findings << "Domínio do Reply-To (#{reply_domain}) difere do domínio do From (#{from_domain})"
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
          @findings << "Nível de confiança de spam da Microsoft alto (#{scl})"
          @score += [scl * 3, 25].min
        end
      end

      # X-Spam headers
      spam_status = headers.match(/X-Spam-Status:\s*(Yes|No)/i)
      if spam_status&.captures&.first&.downcase == "yes"
        @findings << "Marcado como spam por filtro anterior"
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
        @findings << "Cliente de e-mail suspeito: #{mailer_match[1].strip}"
        @score += 15
      end
    end

    def check_received_chain
      received_headers = headers.scan(/Received:\s*from\s+(\S+)/i).flatten
      @details[:received_chain_length] = received_headers.size
      @details[:received_hosts] = received_headers.first(5)
      @details[:sender_ip] = extract_sender_ip
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

    def extract_sender_ip
      received_blocks = headers.scan(/Received:.*?(?=\n\S|\z)/mi)
      ips = received_blocks.flat_map { |block| block.scan(/\b(?:\d{1,3}\.){3}\d{1,3}\b/) }

      ips.reverse.find { |ip| public_ipv4?(ip) }
    end

    def public_ipv4?(ip)
      octets = ip.split(".").map(&:to_i)
      return false unless octets.size == 4 && octets.all? { |octet| octet.between?(0, 255) }

      return false if octets[0] == 10
      return false if octets[0] == 127
      return false if octets[0] == 169 && octets[1] == 254
      return false if octets[0] == 172 && octets[1].between?(16, 31)
      return false if octets[0] == 192 && octets[1] == 168
      return false if octets[0] >= 224

      true
    end

    def build_indeterminate_result
      layer = @email.analysis_layers.find_or_initialize_by(layer_name: LAYER_NAME)
      layer.update!(
        score: 0,
        weight: WEIGHT,
        confidence: 0.1,
        details: {
          outer_from_address: outer_from_address,
          claimed_sender: @email.from_address,
          indirect_sender_context: true
        },
        explanation: "E-mail encaminhado ou reenvelopado: os cabeçalhos de autenticação pertencem ao encaminhador, não ao remetente alegado. Camada tratada como indeterminada.",
        status: "completed"
      )
      layer
    end

    def build_explanation
      if @findings.empty?
        "Verificações de autenticação passaram. SPF: #{@details[:spf]}, DKIM: #{@details[:dkim]}, DMARC: #{@details[:dmarc]}."
      else
        "Encontrado(s) #{@findings.size} problema(s): #{@findings.join('; ')}."
      end
    end
  end
end
