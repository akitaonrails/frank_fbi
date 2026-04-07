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
      .msi .dll .jar .ps1 .reg .inf .hta .cpl .lnk .url
    ].freeze

    SUSPICIOUS_ATTACHMENT_RULES = [
      { category: "archive", extensions: %w[.zip .rar .7z .tar .gz .bz2 .xz .cab], points: 12,
        reason: "Arquivo compactado pode ocultar executáveis, scripts ou documentos perigosos" },
      { category: "disk_image", extensions: %w[.iso .img], points: 18,
        reason: "Imagem de disco pode carregar instaladores e atalhos maliciosos" },
      { category: "macro_document", extensions: %w[.docm .xlsm .pptm .xlam], points: 18,
        reason: "Documento com macro pode executar código ao ser aberto" },
      { category: "onenote", extensions: %w[.one], points: 18,
        reason: "Arquivo do OneNote é um vetor comum para malware e phishing" },
      { category: "mobile_package", extensions: %w[.apk], points: 18,
        reason: "Pacote de aplicativo instala software fora de lojas oficiais" },
      { category: "web_document", extensions: %w[.html .htm .svg], points: 10,
        reason: "Arquivo web anexado pode abrir páginas falsas de login localmente" }
    ].freeze

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
      analyze_attachments
      check_grammar_flags(text)
      detect_mime_mismatch
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
      @suspect_text ||= begin
        text = ForwardedContentExtractor.new(@email.body_text).extract[:suspect_text]
        # If text part is a placeholder (e.g., "An HTML viewer is required"), use stripped HTML instead
        if text.to_s.length < 80 && @email.body_html.to_s.length > text.to_s.length
          stripped = strip_html_to_text(@email.body_html)
          text = stripped if stripped.to_s.length > text.to_s.length
        end
        text
      end
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

    def analyze_attachments
      attachments = @email.attachments_info || []
      @details[:attachment_count] = attachments.size
      @details[:attachment_risks] = []

      dangerous = attachments.select do |att|
        filename = att["filename"].to_s.downcase
        DANGEROUS_EXTENSIONS.any? { |ext| filename.end_with?(ext) }
      end

      if dangerous.any?
        names = dangerous.map { |a| a["filename"] }
        @findings << "Tipo(s) de anexo perigoso(s): #{names.join(', ')}"
        @score += [dangerous.size * 25, 45].min
        @details[:dangerous_attachments] = names
        names.each do |name|
          @details[:attachment_risks] << {
            filename: name,
            severity: "dangerous",
            reason: "Tipo de arquivo executável ou atalho com alto risco de execução"
          }
        end
      end

      suspicious = attachments.filter_map do |att|
        filename = att["filename"].to_s
        downcased = filename.downcase
        rule = SUSPICIOUS_ATTACHMENT_RULES.find do |entry|
          entry[:extensions].any? { |ext| downcased.end_with?(ext) }
        end
        next unless rule

        {
          "filename" => filename,
          "category" => rule[:category],
          "reason" => rule[:reason],
          "points" => rule[:points]
        }
      end

      if suspicious.any?
        names = suspicious.map { |a| a["filename"] }
        @findings << "Anexo(s) altamente suspeito(s): #{names.join(', ')}"
        @score += [suspicious.sum { |a| a["points"].to_i }, 35].min
        @details[:suspicious_attachments] = suspicious
        suspicious.each do |entry|
          @details[:attachment_risks] << {
            filename: entry["filename"],
            severity: "suspicious",
            category: entry["category"],
            reason: entry["reason"]
          }
        end
      end

      # Check for double extensions (e.g., invoice.pdf.exe)
      double_ext = attachments.select do |att|
        att["filename"].to_s.match?(/\.\w+\.\w+$/)
      end
      if double_ext.any?
        names = double_ext.map { |att| att["filename"] }
        @findings << "Anexo(s) com extensão dupla (possível disfarce): #{names.join(', ')}"
        @score += [double_ext.size * 15, 30].min
        @details[:double_extension_attachments] = names
        names.each do |name|
          @details[:attachment_risks] << {
            filename: name,
            severity: "dangerous",
            reason: "Extensão dupla é uma técnica comum para disfarçar o tipo real do arquivo"
          }
        end
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

    # Detects significant divergence between text/plain and text/html MIME parts.
    # An attacker can place innocent content in text/plain (which the LLM analyzes)
    # and the real scam in text/html (which the victim reads).
    def detect_mime_mismatch
      text_plain = @email.body_text.to_s.strip
      html_raw = @email.body_html.to_s.strip
      return if text_plain.blank? || html_raw.blank?

      text_from_html = strip_html_to_text(html_raw).strip
      return if text_from_html.blank?

      # Skip if either is very short (placeholder/stub)
      return if text_plain.length < 80 || text_from_html.length < 80

      # Calculate word overlap between the two versions
      words_plain = text_plain.downcase.scan(/\w{3,}/).to_set
      words_html = text_from_html.downcase.scan(/\w{3,}/).to_set
      return if words_plain.empty? || words_html.empty?

      intersection = words_plain & words_html
      union = words_plain | words_html
      similarity = intersection.size.to_f / union.size

      if similarity < 0.30
        @details[:mime_mismatch_detected] = true
        @details[:mime_similarity] = (similarity * 100).round
        @findings << "Divergência significativa entre text/plain e text/html (#{(similarity * 100).round}% similaridade) — possível tentativa de enganar análise automatizada"
        @score += 30
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

    def strip_html_to_text(html)
      Rails::HTML5::SafeListSanitizer.new.sanitize(html.to_s, tags: []).gsub(/\s+/, " ").strip
    rescue StandardError
      html.to_s.gsub(/<[^>]+>/, " ").gsub(/\s+/, " ").strip
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
