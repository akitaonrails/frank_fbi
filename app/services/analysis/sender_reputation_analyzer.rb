module Analysis
  class SenderReputationAnalyzer
    LAYER_NAME = "sender_reputation"
    WEIGHT = AnalysisLayer::WEIGHTS[LAYER_NAME]

    FREEMAIL_DOMAINS = %w[
      gmail.com yahoo.com hotmail.com outlook.com aol.com
      mail.com protonmail.com icloud.com yandex.com zoho.com
      gmx.com fastmail.com tutanota.com live.com msn.com
    ].freeze

    def initialize(email)
      @email = email
      @findings = []
      @score = 0
      @details = {}
    end

    def analyze
      domain = @email.sender_domain
      return build_no_domain_result unless domain

      check_local_reputation(domain)
      check_domain_age(domain)
      check_blacklists(domain)
      check_freemail(domain)
      check_sender_history
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

      # Update known domain/sender records
      update_known_records(domain)

      layer
    end

    private

    def check_local_reputation(domain)
      known = KnownDomain.find_by(domain: domain)
      return unless known

      @details[:previously_seen] = true
      @details[:times_seen] = known.times_seen
      @details[:local_fraud_ratio] = known.fraud_ratio

      if known.fraud_ratio > 0.7 && known.times_seen >= 3
        @findings << "Domínio com alta taxa de fraude em nosso banco de dados (#{(known.fraud_ratio * 100).round}%)"
        @score += 25
      elsif known.fraud_ratio > 0.4
        @findings << "Domínio com taxa moderada de fraude (#{(known.fraud_ratio * 100).round}%)"
        @score += 10
      end
    end

    def check_domain_age(domain)
      whois = WhoisLookupService.new(domain).lookup
      return unless whois

      age = whois[:domain_age_days] || whois["domain_age_days"]
      @details[:domain_age_days] = age
      @details[:registrar] = whois[:registrar] || whois["registrar"]

      if age
        if age < 30
          @findings << "Domínio registrado há menos de 30 dias (#{age} dias)"
          @score += 30
        elsif age < 90
          @findings << "Domínio relativamente novo (#{age} dias)"
          @score += 15
        elsif age < 365
          @score += 5
        end
      end
    end

    def check_blacklists(domain)
      ip = extract_sender_ip
      checker = DnsBlacklistChecker.new(domain, ip: ip)
      results = checker.check

      listed = results.select { |_, v| v[:listed] }
      @details[:blacklist_results] = results
      @details[:blacklist_hits] = listed.size

      if listed.any?
        names = listed.values.map { |v| v[:blacklist_name] }
        @findings << "Listado em #{listed.size} lista(s) negra(s): #{names.join(', ')}"
        @score += [listed.size * 15, 40].min
      end
    end

    def check_freemail(domain)
      if FREEMAIL_DOMAINS.include?(domain.downcase)
        @details[:freemail] = true
        # Not inherently suspicious, but note it
      else
        @details[:freemail] = false
      end
    end

    def check_sender_history
      sender = KnownSender.find_by(email_address: @email.from_address)
      return unless sender

      @details[:sender_emails_analyzed] = sender.emails_analyzed
      @details[:sender_fraud_ratio] = sender.fraud_ratio

      if sender.fraud_ratio > 0.8 && sender.emails_analyzed >= 2
        @findings << "Remetente com taxa de fraude muito alta (#{(sender.fraud_ratio * 100).round}%)"
        @score += 20
      end
    end

    def extract_sender_ip
      # Try to get from header auth analysis
      header_layer = @email.analysis_layers.find_by(layer_name: "header_auth")
      header_layer&.details&.dig("sender_ip")
    end

    def calculate_score
      @score = [@score, 100].min
    end

    def calculate_confidence
      signals = 0
      signals += 1 if @details[:domain_age_days]
      signals += 1 if @details[:blacklist_results]&.any?
      signals += 1 if @details[:previously_seen]

      base = 0.4 + (signals * 0.2)
      [base, 1.0].min
    end

    def build_explanation
      if @findings.empty?
        age_text = @details[:domain_age_days] ? "#{@details[:domain_age_days]} dias" : "idade desconhecida"
        "Domínio do remetente #{@email.sender_domain} parece normal (#{age_text})."
      else
        "Encontrado(s) #{@findings.size} problema(s): #{@findings.join('; ')}."
      end
    end

    def update_known_records(domain)
      KnownDomain.find_or_create_by!(domain: domain) do |d|
        d.times_seen = 0
      end

      if @email.from_address
        known_domain = KnownDomain.find_by(domain: domain)
        KnownSender.find_or_create_by!(email_address: @email.from_address) do |s|
          s.known_domain = known_domain
          s.emails_analyzed = 0
        end
      end
    end

    def build_no_domain_result
      layer = @email.analysis_layers.find_or_initialize_by(layer_name: LAYER_NAME)
      layer.update!(
        score: 50,
        weight: WEIGHT,
        confidence: 0.3,
        details: { error: "No sender domain found" },
        explanation: "Não foi possível determinar o domínio do remetente para análise de reputação.",
        status: "completed"
      )
      layer
    end
  end
end
