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
      /\b(within\s+\d+\s+hours?|within\s+24|48\s+hours?)\b/i,
      /\b(immediate|urgent)\s+action\s+(required|needed)\b/i,
      /\bmandatory\s+(update|verification|action|upgrade|security)\b/i,
      /\bdeadline\s*:\s*\w+\s+\d+/i,
      /\bmay\s+result\s+in\s+(restricted|limited|loss|suspend)/i
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
      /\bfailure\s+to\s+(comply|respond|verify)\b/i,
      /\brestricted\s+access\s+to\s+your\b/i,
      /\bcompromise\s+your\s+(access|funds?|account|assets?|data|security)\b/i,
      /\bexposed\s+to\s+(risks?|threats?|vulnerabilit)/i
    ].freeze

    # --- PT-BR patterns ---

    WHATSAPP_PATTERNS = [
      /\bhttps?:\/\/wa\.me\//i,
      /\bhttps?:\/\/wa\.link\//i,
      /\bhttps?:\/\/chat\.whatsapp\.com\//i,
      /\bhttps?:\/\/api\.whatsapp\.com\//i
    ].freeze

    BROKEN_UNSUBSCRIBE_PATTERNS = [
      /%%unsubscribelink%%/i,
      /%25%25unsubscribe/i,
      /\{\{unsubscribe\}\}/i,
      /\{unsubscribe_url\}/i,
      /%%email%%/i,
      /%25%25email%25%25/i
    ].freeze

    URGENCY_PATTERNS_PTBR = [
      /\b(urgente|imediatamente|agora\s+mesmo)\b/i,
      /\b(n[ãa]o\s+perca|[úu]ltima\s+chance|prazo\s+limitado)\b/i,
      /\b(vagas?\s+limitadas?|aja\s+agora|corra|aproveite\s+j[áa])\b/i,
      /\b(oferta\s+(exclusiva|imperd[íi]vel)|tempo\s+limitado)\b/i,
      /\b(antes\s+que\s+acabe|restam\s+poucas?\s+vagas?)\b/i
    ].freeze

    FINANCIAL_PATTERNS_PTBR = [
      /\b(taxa\s+do\s+mercado|cons[óo]rcio|cr[ée]dito\s+contemplado)\b/i,
      /\b(investimento|rendimento|transfer[êe]ncia\s+banc[áa]ria)\b/i,
      /\b(empr[ée]stimo|carta\s+contemplada|aporte)\b/i,
      /\b(compra\s+de\s+cr[ée]dito|menor\s+taxa|taxa\s+zero)\b/i,
      /\b(sem\s+juros|parcelas?\s+fixas?|antecipa[çc][ãa]o)\b/i,
      /\b(pix|boleto|dep[óo]sito\s+banc[áa]rio)\b/i
    ].freeze

    PII_REQUEST_PATTERNS_PTBR = [
      /\b(CPF|RG|CNPJ)\b/,
      /\b(dados?\s+pessoais?|dados?\s+banc[áa]rios?)\b/i,
      /\b(n[úu]mero\s+do\s+cart[ãa]o|senha|c[óo]digo\s+de\s+seguran[çc]a)\b/i,
      /\b(comprovante\s+de\s+resid[êe]ncia|certid[ãa]o)\b/i,
      /\b(chave\s+pix|conta\s+banc[áa]ria)\b/i
    ].freeze

    AUTHORITY_IMPERSONATION_PTBR = [
      /\b(Pol[íi]cia\s+Federal|Pol[íi]cia\s+Civil)\b/i,
      /\b(Receita\s+Federal|Banco\s+Central)\b/i,
      /\b(Minist[ée]rio\s+(P[úu]blico|da\s+\w+))\b/i,
      /\b(Tribunal\s+de\s+Justi[çc]a|Procuradoria)\b/i,
      /\b(INSS|Detran|Serasa|SPC)\b/,
      /\b(Caixa\s+Econ[ôo]mica|Banco\s+do\s+Brasil)\b/i
    ].freeze

    PHISHING_PHRASES_PTBR = [
      /\bclique\s+aqui\s+para\b/i,
      /\bsua\s+conta\s+foi\s+(bloqueada|suspensa|comprometida)/i,
      /\bconfirme\s+seus\s+dados\b/i,
      /\batualize\s+seu\s+cadastro\b/i,
      /\bverifique\s+sua\s+identidade\b/i,
      /\bacesse\s+o\s+link\s+(abaixo|a\s+seguir)\b/i
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
      detect_whatsapp_links
      detect_broken_unsubscribe
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
      [suspect_text, @email.subject].compact.join(" ")
    end

    def suspect_text
      @suspect_text ||= ForwardedContentExtractor.new(@email.body_text).extract[:suspect_text]
    end

    def analyze_urls
      urls = @email.extracted_urls || []
      @details[:url_count] = urls.size
      @details[:urls] = urls.first(20)

      # Extract unique domains from URLs
      domains = urls.filter_map { |u| URI.parse(u).host rescue nil }.uniq
      @details[:url_domains] = domains

      if urls.size > 10
        @findings << "Contém um número incomum de URLs (#{urls.size})"
        @score += 5
      end
    end

    def analyze_url_mismatches
      html = strip_submitter_html(@email.body_html.to_s)
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
        @findings << "Encontrada(s) #{mismatches.size} divergência(s) entre texto e link — técnica clássica de phishing"
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
        @findings << "Contém #{shortened.size} URL(s) encurtada(s) que ocultam o destino real"
        @score += shortened.size * 8
        @details[:shortened_urls] = shortened
      end
    end

    def detect_whatsapp_links
      text = combined_text
      html = @email.body_html.to_s
      full_content = "#{text} #{html}"

      matches = WHATSAPP_PATTERNS.count { |p| full_content.match?(p) }
      @details[:whatsapp_matches] = matches

      if matches > 0
        @findings << "Contém #{matches} link(s) do WhatsApp — desvio de canais comerciais normais"
        @score += [matches * 10, 20].min
      end
    end

    def detect_broken_unsubscribe
      html = @email.body_html.to_s
      text = combined_text
      full_content = "#{text} #{html}"

      matches = BROKEN_UNSUBSCRIBE_PATTERNS.count { |p| full_content.match?(p) }
      @details[:broken_unsubscribe_matches] = matches

      if matches > 0
        @findings << "Contém #{matches} variável(is) de template não resolvida(s) — indica e-mail em massa mal configurado"
        @score += [matches * 8, 15].min
      end
    end

    def analyze_patterns(text)
      # English patterns
      check_pattern_group(text, URGENCY_PATTERNS, "urgency", "Linguagem de urgência/pressão detectada", 8)
      check_pattern_group(text, FINANCIAL_PATTERNS, "financial", "Indicadores de fraude financeira detectados", 12)
      check_pattern_group(text, PII_REQUEST_PATTERNS, "pii_request", "Solicitação de informações pessoais/sensíveis", 15)
      check_pattern_group(text, AUTHORITY_IMPERSONATION, "authority", "Impersonação de autoridade/governo detectada", 12)
      check_pattern_group(text, PHISHING_PHRASES, "phishing", "Padrões de linguagem de phishing detectados", 10)

      # PT-BR patterns
      check_pattern_group(text, URGENCY_PATTERNS_PTBR, "urgency_ptbr", "Linguagem de urgência/pressão em português detectada", 8)
      check_pattern_group(text, FINANCIAL_PATTERNS_PTBR, "financial_ptbr", "Indicadores de fraude financeira em português detectados", 12)
      check_pattern_group(text, PII_REQUEST_PATTERNS_PTBR, "pii_request_ptbr", "Solicitação de dados pessoais/sensíveis em português", 15)
      check_pattern_group(text, AUTHORITY_IMPERSONATION_PTBR, "authority_ptbr", "Impersonação de autoridade brasileira detectada", 12)
      check_pattern_group(text, PHISHING_PHRASES_PTBR, "phishing_ptbr", "Padrões de phishing em português detectados", 10)
    end

    def check_pattern_group(text, patterns, key, finding_message, score_per_match)
      matches = patterns.count { |p| text.match?(p) }
      @details[:"#{key}_matches"] = matches

      if matches > 0
        @findings << "#{finding_message} (#{matches} padrão(ões))"
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
        @findings << "Tipo(s) de anexo perigoso(s): #{names.join(', ')}"
        @score += 25
        @details[:dangerous_attachments] = names
      end

      # Check for double extensions (e.g., invoice.pdf.exe)
      double_ext = attachments.select do |att|
        att["filename"].to_s.match?(/\.\w+\.\w+$/)
      end
      if double_ext.any?
        @findings << "Anexo(s) com extensão dupla (possível disfarce)"
        @score += 15
      end
    end

    def check_grammar_flags(text)
      # Check for ALL CAPS subject
      subject = @email.subject.to_s
      if subject.length > 10 && subject == subject.upcase && subject.match?(/[A-Z]/)
        @findings << "Linha de assunto inteiramente em MAIÚSCULAS"
        @score += 8
        @details[:all_caps_subject] = true
      end

      # Check for excessive exclamation/question marks
      if subject.count("!") >= 3 || text.scan(/!{2,}/).any?
        @findings << "Excesso de pontos de exclamação no e-mail"
        @score += 5
        @details[:excessive_punctuation] = true
      end
    end

    def calculate_score
      @score = [@score, 100].min
    end

    def calculate_confidence
      text_length = suspect_text.to_s.length
      if text_length > 200
        1.0
      elsif text_length > 50
        0.8
      else
        0.5
      end
    end

    def strip_submitter_html(html)
      html.gsub(/<div class="gmail_signature"[^>]*>.*?<\/div>/mi, "")
    end

    def build_explanation
      if @findings.empty?
        "Nenhum padrão de conteúdo suspeito detectado. #{@details[:url_count]} URL(s) encontrada(s), #{@details[:attachment_count]} anexo(s)."
      else
        "Encontrado(s) #{@findings.size} problema(s): #{@findings.join('; ')}."
      end
    end
  end
end
