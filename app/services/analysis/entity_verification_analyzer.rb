require "json"

module Analysis
  class EntityVerificationAnalyzer
    LAYER_NAME = "entity_verification"
    WEIGHT = AnalysisLayer::WEIGHTS[LAYER_NAME]
    MODEL = "anthropic/claude-sonnet-4.6"
    SAFE_REFERENCE_HOSTS = %w[
      linkedin.com www.linkedin.com
      x.com www.x.com
      twitter.com www.twitter.com
      facebook.com www.facebook.com
      instagram.com www.instagram.com
      github.com www.github.com
      youtube.com www.youtube.com
      tiktok.com www.tiktok.com
      threads.net www.threads.net
    ].freeze

    def initialize(email)
      @email = email
    end

    def analyze
      layer = @email.analysis_layers.find_or_initialize_by(layer_name: LAYER_NAME)
      layer.update!(weight: WEIGHT, status: "running")

      # Always run direct domain verification (WHOIS + DNS) — no external search API needed
      domain_info = verify_domain_directly

      # Extract entities from email and prior layers
      prior_layers = @email.analysis_layers.where(status: "completed").where.not(layer_name: LAYER_NAME)
      entities = EntityExtractionService.new(@email, prior_layers: prior_layers).extract

      # Try LLM + Brave Search for OSINT verification
      llm_result = run_llm_verification(entities, domain_info)

      # Merge direct domain verification with LLM results
      merged = merge_results(llm_result, domain_info)

      layer.update!(
        score: merged[:score],
        weight: WEIGHT,
        confidence: merged[:confidence],
        details: {
          extracted_entities: entities,
          verdict_summary: merged[:verdict_summary],
          sender_verified: merged[:sender_verified],
          domain_verified: merged[:domain_verified],
          entity_mismatches: merged[:entity_mismatches],
          key_findings: merged[:key_findings],
          search_summary: merged[:search_summary],
          reference_links: merged[:reference_links],
          domain_whois: domain_info[:whois],
          domain_age_days: domain_info[:age_days],
          domain_registrar: domain_info[:registrar],
          domain_blacklisted: domain_info[:blacklisted],
          domain_blacklist_hits: domain_info[:blacklist_hits],
          model: MODEL
        },
        explanation: merged[:verdict_summary],
        status: "completed"
      )

      layer
    rescue => e
      Rails.logger.error("EntityVerificationAnalyzer: #{e.message}")
      handle_failure(e)
    end

    private

    def verify_domain_directly
      domain = @email.sender_domain
      return { verified: false, findings: ["Domínio do remetente não disponível"] } unless domain

      info = { domain: domain, verified: nil, findings: [], age_days: nil, registrar: nil,
               blacklisted: false, blacklist_hits: 0 }

      # WHOIS lookup
      begin
        whois = WhoisLookupService.new(domain).lookup
        if whois
          info[:age_days] = whois[:domain_age_days] || whois["domain_age_days"]
          info[:registrar] = whois[:registrar] || whois["registrar"]
          info[:whois] = { age_days: info[:age_days], registrar: info[:registrar],
                           created_date: whois[:created_date] || whois["created_date"] }

          if info[:age_days]
            if info[:age_days] > 365
              info[:findings] << "Domínio #{domain} registrado há #{info[:age_days]} dias (#{info[:registrar] || 'registrador desconhecido'})"
              info[:verified] = true
            elsif info[:age_days] > 90
              info[:findings] << "Domínio #{domain} relativamente novo: #{info[:age_days]} dias (#{info[:registrar] || 'registrador desconhecido'})"
              info[:verified] = true
            elsif info[:age_days] < 30
              info[:findings] << "Domínio #{domain} muito recente: apenas #{info[:age_days]} dias — alto risco"
              info[:verified] = false
            else
              info[:findings] << "Domínio #{domain} novo: #{info[:age_days]} dias (#{info[:registrar] || 'registrador desconhecido'})"
              info[:verified] = false
            end
          else
            info[:findings] << "Domínio #{domain} encontrado no WHOIS mas sem data de registro"
            info[:verified] = true
          end
        else
          info[:findings] << "Consulta WHOIS para #{domain} não retornou dados"
        end
      rescue => e
        Rails.logger.warn("EntityVerificationAnalyzer WHOIS failed: #{e.message}")
        info[:findings] << "Consulta WHOIS para #{domain} falhou: #{e.message}"
      end

      # DNS blacklist check
      begin
        ip = extract_sender_ip
        checker = DnsBlacklistChecker.new(domain, ip: ip)
        results = checker.check
        listed = results.select { |_, v| v[:listed] }

        if listed.any?
          names = listed.values.map { |v| v[:blacklist_name] }
          info[:blacklisted] = true
          info[:blacklist_hits] = listed.size
          info[:findings] << "Domínio #{domain} listado em #{listed.size} lista(s) negra(s): #{names.join(', ')}"
          info[:verified] = false
        else
          info[:findings] << "Domínio #{domain} não consta em listas negras de DNS"
        end
      rescue => e
        Rails.logger.warn("EntityVerificationAnalyzer DNS blacklist failed: #{e.message}")
      end

      info
    end

    def extract_sender_ip
      header_layer = @email.analysis_layers.find_by(layer_name: "header_auth")
      header_layer&.details&.dig("sender_ip")
    end

    def run_llm_verification(entities, domain_info)
      start_time = Process.clock_gettime(Process::CLOCK_MONOTONIC)

      prompt = Prompts::EntityVerificationPrompt.new(@email, entities).build

      # Append domain verification data to prompt so LLM has it even if Brave fails
      prompt += domain_context(domain_info)

      chat = build_chat
      response = chat.ask(prompt)

      elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - start_time

      parsed = parse_response(response.content)
      parsed[:response_time_seconds] = elapsed.round(2)
      parsed[:input_tokens] = response.input_tokens
      parsed[:output_tokens] = response.output_tokens
      parsed[:llm_succeeded] = true
      parsed
    rescue => e
      Rails.logger.warn("EntityVerificationAnalyzer LLM failed: #{e.message}")
      {
        score: nil,
        confidence: 0.0,
        verdict_summary: nil,
        sender_verified: nil,
        domain_verified: nil,
        entity_mismatches: [],
        key_findings: [],
        search_summary: "Verificação por IA falhou: #{e.message}",
        reference_links: [],
        llm_succeeded: false
      }
    end

    def domain_context(domain_info)
      lines = ["\n\n## Dados de Verificação Direta do Domínio (WHOIS + DNS)\n"]

      if domain_info[:age_days]
        lines << "- Idade do domínio: #{domain_info[:age_days]} dias"
      end
      if domain_info[:registrar]
        lines << "- Registrador: #{domain_info[:registrar]}"
      end
      if domain_info[:blacklisted]
        lines << "- ALERTA: Domínio listado em #{domain_info[:blacklist_hits]} lista(s) negra(s)"
      else
        lines << "- Domínio não consta em listas negras de DNS"
      end

      domain_info[:findings].each { |f| lines << "- #{f}" }

      lines << "\nUse estes dados para complementar sua análise, especialmente se as buscas web falharem."
      lines.join("\n")
    end

    def merge_results(llm_result, domain_info)
      if llm_result[:llm_succeeded] && llm_result[:confidence].to_f > 0.3
        # LLM succeeded with reasonable confidence — use its results, enrich with domain data
        merged = llm_result.dup
        merged[:key_findings] = (merged[:key_findings] + domain_info[:findings]).uniq.first(10)

        # If LLM couldn't verify domain but WHOIS did, update
        if merged[:domain_verified].nil? && domain_info[:verified] != nil
          merged[:domain_verified] = domain_info[:verified]
        end

        merged[:search_summary] = [merged[:search_summary], domain_data_summary(domain_info)].compact.join(" ")
        merged[:reference_links] = sanitize_reference_links(merged[:reference_links], domain_info[:domain])
        merged
      else
        # LLM failed or very low confidence — build result from domain verification alone
        build_domain_only_result(domain_info, llm_result)
      end
    end

    def build_domain_only_result(domain_info, llm_result)
      score = 50 # neutral baseline

      if domain_info[:blacklisted]
        score += 25
      end

      if domain_info[:age_days]
        if domain_info[:age_days] < 30
          score += 20
        elsif domain_info[:age_days] < 90
          score += 10
        elsif domain_info[:age_days] > 365
          score -= 15
        end
      end

      score = score.clamp(0, 100)

      findings = domain_info[:findings].dup
      if llm_result[:search_summary].present?
        findings << llm_result[:search_summary]
      end

      confidence = domain_info[:age_days] ? 0.5 : 0.3

      verdict = if domain_info[:blacklisted]
        "Domínio listado em listas negras. #{domain_data_summary(domain_info)}"
      elsif domain_info[:age_days] && domain_info[:age_days] > 365
        "Domínio estabelecido (#{domain_info[:age_days]} dias). Verificação OSINT indisponível — resultado baseado em WHOIS e DNS."
      elsif domain_info[:age_days]
        "Domínio com #{domain_info[:age_days]} dias. Verificação OSINT indisponível — resultado baseado em WHOIS e DNS."
      else
        "Verificação parcial: dados WHOIS indisponíveis, busca OSINT falhou."
      end

      {
        score: score,
        confidence: confidence,
        verdict_summary: verdict,
        sender_verified: nil,
        domain_verified: domain_info[:verified],
        entity_mismatches: [],
        key_findings: findings.first(10),
        search_summary: domain_data_summary(domain_info),
        reference_links: []
      }
    end

    def domain_data_summary(domain_info)
      parts = []
      if domain_info[:age_days]
        parts << "WHOIS: #{domain_info[:age_days]} dias"
        parts << "registrador: #{domain_info[:registrar]}" if domain_info[:registrar]
      end
      if domain_info[:blacklisted]
        parts << "#{domain_info[:blacklist_hits]} lista(s) negra(s)"
      else
        parts << "sem listas negras"
      end
      parts.any? ? "Verificação direta: #{parts.join(', ')}." : ""
    end

    def build_chat
      chat = RubyLLM.chat(model: MODEL)
      chat.with_tool(BraveWebSearch)
      chat
    end

    def parse_response(content)
      data = extract_json(content.to_s)

      {
        score: data["score"]&.to_i&.clamp(0, 100) || 50,
        confidence: data["confidence"]&.to_f&.clamp(0.0, 1.0) || 0.5,
        verdict_summary: data["verdict_summary"].to_s,
        sender_verified: data["sender_verified"],
        domain_verified: data["domain_verified"],
        entity_mismatches: Array(data["entity_mismatches"]).map(&:to_s).first(10),
        key_findings: Array(data["key_findings"]).map(&:to_s).first(10),
        search_summary: data["search_summary"].to_s,
        reference_links: sanitize_reference_links(data["reference_links"], @email.sender_domain)
      }
    rescue JSON::ParserError => e
      Rails.logger.warn("EntityVerificationAnalyzer: JSON parse failed: #{e.message}")
      {
        score: 50,
        confidence: 0.2,
        verdict_summary: "Falha ao interpretar resposta da verificação de entidade",
        sender_verified: nil,
        domain_verified: nil,
        entity_mismatches: [],
        key_findings: ["Falha na interpretação da resposta"],
        search_summary: "Parse error: #{content.to_s[0..200]}",
        reference_links: []
      }
    end

    def extract_json(text)
      if text =~ /```json\s*(.*?)```/mi
        return JSON.parse($1.strip)
      end

      start_idx = text.index("{")
      end_idx = text.rindex("}")
      if start_idx && end_idx && end_idx > start_idx
        return JSON.parse(text[start_idx..end_idx])
      end

      JSON.parse(text.strip)
    end

    def handle_failure(error)
      # Even on total failure, try direct domain verification
      domain_info = begin
        verify_domain_directly
      rescue
        { verified: nil, findings: [], age_days: nil, registrar: nil, blacklisted: false, blacklist_hits: 0 }
      end

      result = build_domain_only_result(domain_info, { search_summary: "Erro: #{error.message}" })

      layer = @email.analysis_layers.find_or_initialize_by(layer_name: LAYER_NAME)
      layer.update!(
        score: result[:score],
        weight: WEIGHT,
        confidence: result[:confidence],
        details: {
          error: error.message,
          domain_whois: domain_info[:whois],
          domain_age_days: domain_info[:age_days],
          domain_registrar: domain_info[:registrar],
          domain_blacklisted: domain_info[:blacklisted],
          domain_verified: domain_info[:verified],
          key_findings: result[:key_findings],
          search_summary: result[:search_summary],
          reference_links: []
        },
        explanation: result[:verdict_summary],
        status: "completed"
      )
      layer
    end

    def sanitize_reference_links(raw_links, sender_domain)
      Array(raw_links).filter_map do |link|
        normalize_reference_link(link, sender_domain)
      end.uniq { |link| link[:url] }.first(5)
    end

    def normalize_reference_link(link, sender_domain)
      return nil unless link.is_a?(Hash)

      url = link["url"] || link[:url]
      label = (link["label"] || link[:label]).to_s.strip
      platform = (link["platform"] || link[:platform]).to_s.strip.downcase
      return nil if url.blank?

      uri = URI.parse(url)
      return nil unless uri.is_a?(URI::HTTPS)

      host = uri.host.to_s.downcase
      return nil if host.blank? || host.start_with?("xn--")
      return nil unless safe_reference_host?(host, sender_domain)

      uri.query = nil
      uri.fragment = nil

      {
        label: label.presence || host,
        url: uri.to_s,
        platform: platform.presence || classify_platform(host, sender_domain)
      }
    rescue URI::InvalidURIError
      nil
    end

    def safe_reference_host?(host, sender_domain)
      return true if SAFE_REFERENCE_HOSTS.include?(host)
      return false if sender_domain.blank?

      host == sender_domain || host.end_with?(".#{sender_domain}")
    end

    def classify_platform(host, sender_domain)
      return "site_oficial" if sender_domain.present? && (host == sender_domain || host.end_with?(".#{sender_domain}"))
      return "linkedin" if host.include?("linkedin.com")
      return "x" if host == "x.com" || host == "www.x.com"
      return "twitter" if host.include?("twitter.com")
      return "facebook" if host.include?("facebook.com")
      return "instagram" if host.include?("instagram.com")
      return "github" if host.include?("github.com")
      return "youtube" if host.include?("youtube.com")
      return "tiktok" if host.include?("tiktok.com")
      return "threads" if host.include?("threads.net")

      "other"
    end
  end
end
