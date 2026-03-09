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
