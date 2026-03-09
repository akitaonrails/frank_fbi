module Triage
  class ReportRenderer
    VERDICT_COLORS = {
      "legitimate" => "#22c55e",
      "suspicious_likely_ok" => "#f59e0b",
      "suspicious_likely_fraud" => "#f97316",
      "fraudulent" => "#ef4444"
    }.freeze

    VERDICT_LABELS = {
      "legitimate" => "SEGURO",
      "suspicious_likely_ok" => "PROVAVELMENTE SEGURO",
      "suspicious_likely_fraud" => "SUSPEITO (Provável Golpe)",
      "fraudulent" => "PERIGOSO"
    }.freeze

    VERDICT_EMOJIS = {
      "legitimate" => "\u2705",
      "suspicious_likely_ok" => "\u26A0\uFE0F",
      "suspicious_likely_fraud" => "\u{1F6A8}",
      "fraudulent" => "\u{1F6D1}"
    }.freeze

    LAYER_LABELS = {
      "triage_url_scan" => "Verificação de URLs",
      "triage_file_scan" => "Verificação de Arquivos",
      "triage_llm" => "Avaliação por IA"
    }.freeze

    def initialize(email)
      @email = email
      @layers = email.analysis_layers.order(:layer_name)
      @llm_verdicts = email.llm_verdicts
    end

    def to_html
      <<~HTML
        <!DOCTYPE html>
        <html>
        <head>
          <meta charset="utf-8">
          <style>
            body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; color: #1f2937; font-size: 14px; line-height: 1.5; }
            .banner { padding: 16px; border-radius: 8px; text-align: center; margin-bottom: 20px; color: white; }
            .score-big { font-size: 36px; font-weight: bold; }
            .verdict-label { font-size: 18px; font-weight: 600; margin-top: 4px; }
            .section { margin-bottom: 16px; }
            .section h3 { font-size: 14px; color: #6b7280; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 8px; border-bottom: 1px solid #e5e7eb; padding-bottom: 4px; }
            .layer { padding: 8px 12px; margin-bottom: 6px; border-radius: 6px; background: #f9fafb; }
            .layer-header { width: 100%; border-collapse: collapse; }
            .layer-header td { font-weight: 600; padding: 0; }
            .layer-score { font-weight: bold; text-align: right; }
            .layer-explanation { font-size: 13px; color: #4b5563; margin-top: 4px; }
            .score-bar { height: 6px; border-radius: 3px; background: #e5e7eb; margin-top: 4px; }
            .score-fill { height: 100%; border-radius: 3px; }
            .findings { padding-left: 20px; margin: 8px 0; }
            .findings li { font-size: 13px; color: #374151; margin-bottom: 4px; }
            .url-safe { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; word-break: break-all; color: #374151; background: #f3f4f6; padding: 2px 6px; border-radius: 3px; }
            .critical-alert { background: #fef2f2; border: 2px solid #ef4444; border-radius: 8px; padding: 12px 16px; margin-bottom: 8px; }
            .critical-alert strong { color: #dc2626; }
            .safe-notice { background: #f0fdf4; border: 2px solid #22c55e; border-radius: 8px; padding: 12px 16px; margin-bottom: 8px; }
            .safe-notice strong { color: #166534; }
            .recommendation { background: #eff6ff; border: 2px solid #3b82f6; border-radius: 8px; padding: 12px 16px; margin-bottom: 16px; }
            .recommendation strong { color: #1d4ed8; }
            .footer { font-size: 11px; color: #9ca3af; text-align: center; margin-top: 24px; border-top: 1px solid #e5e7eb; padding-top: 12px; }
          </style>
        </head>
        <body>
          #{banner_html}

          #{safety_recommendation_html}

          #{critical_alerts_html}

          <div class="section">
            <h3>Mensagem Analisada</h3>
            <p><strong>De:</strong> #{h @email.from_name} &lt;#{h @email.from_address}&gt;</p>
            <p><strong>Assunto:</strong> #{h @email.subject}</p>
          </div>

          #{url_scan_html}

          #{file_scan_html}

          #{llm_assessment_html}

          #{score_breakdown_html}

          <div class="footer">
            <p>Frank FBI &mdash; Triagem de Mensagens de Aplicativos</p>
            <p>Esta an&aacute;lise &eacute; automatizada e deve ser usada como orienta&ccedil;&atilde;o.</p>
          </div>
        </body>
        </html>
      HTML
    end

    def to_text
      lines = []
      emoji = VERDICT_EMOJIS[@email.verdict] || ""
      lines << "#{emoji} FRANK FBI - TRIAGEM DE MENSAGEM"
      lines << "=" * 50
      lines << ""
      lines << "VEREDITO: #{VERDICT_LABELS[@email.verdict] || @email.verdict&.upcase}"
      lines << "PONTUAÇÃO: #{@email.final_score}/100"

      # Safety recommendation
      recommendation = extract_safety_recommendation
      if recommendation.present?
        lines << ""
        lines << "RECOMENDAÇÃO: #{recommendation}"
      end

      # Critical alerts
      alerts = collect_critical_alerts
      if alerts.any?
        lines << ""
        lines << "!!! ALERTA !!!"
        alerts.each { |a| lines << "  #{a}" }
      end

      lines << ""
      lines << "--- Mensagem Analisada ---"
      lines << "De: #{@email.from_name} <#{@email.from_address}>"
      lines << "Assunto: #{@email.subject}"

      # URL scan results
      url_layer = find_layer("triage_url_scan")
      if url_layer
        lines << ""
        lines << "--- Verificação de URLs ---"
        lines << "  Pontuação: #{url_layer.score}/100"
        lines << "  #{url_layer.explanation}"
        urls_detail = url_layer.details || {}
        Array(urls_detail["urlhaus"] || urls_detail[:urlhaus]).each do |entry|
          url = entry["url"] || entry[:url]
          malicious = entry["malicious"] || entry[:malicious]
          status = malicious ? "MALICIOSA" : "OK"
          lines << "  #{safe_url_text(url)} [#{status}]"
        end
        Array(urls_detail["virustotal"] || urls_detail[:virustotal]).each do |entry|
          url = entry["url"] || entry[:url]
          detections = entry["detections"] || entry[:detections]
          status = detections.to_i > 0 ? "#{detections} detecções" : "OK"
          lines << "  #{safe_url_text(url)} [VT: #{status}]"
        end
      end

      # File scan results
      file_layer = find_layer("triage_file_scan")
      if file_layer
        lines << ""
        lines << "--- Verificação de Arquivos ---"
        lines << "  Pontuação: #{file_layer.score}/100"
        lines << "  #{file_layer.explanation}"
      end

      # LLM assessment
      if @llm_verdicts.any?
        lines << ""
        lines << "--- Avaliação por IA ---"
        @llm_verdicts.each do |v|
          lines << "  #{v.score}/100 — #{v.reasoning}"
        end
      end

      # Score breakdown
      lines << ""
      lines << "--- Detalhamento ---"
      @layers.each do |layer|
        lines << "  #{layer_label(layer.layer_name)}: #{layer.score}/100 (confiança: #{(layer.confidence * 100).round}%)"
      end

      lines << ""
      lines << "-" * 50
      lines << "Frank FBI - Triagem de Mensagens de Aplicativos"
      lines << "Esta análise é automatizada e deve ser usada como orientação."
      lines.join("\n")
    end

    private

    def h(text)
      ERB::Util.html_escape(text.to_s)
    end

    def find_layer(name)
      @layers.find { |l| l.layer_name == name }
    end

    def layer_label(name)
      LAYER_LABELS[name] || name.titleize
    end

    # Truncate URL in the middle so it's never clickable but still identifiable
    def safe_url(url, max_length = 60)
      url = url.to_s
      return h(url) if url.length <= max_length

      prefix_len = (max_length * 0.6).to_i
      suffix_len = (max_length * 0.3).to_i
      h("#{url[0...prefix_len]}...#{url[-suffix_len..]}")
    end

    def safe_url_text(url, max_length = 60)
      url = url.to_s
      return url if url.length <= max_length

      prefix_len = (max_length * 0.6).to_i
      suffix_len = (max_length * 0.3).to_i
      "#{url[0...prefix_len]}...#{url[-suffix_len..]}"
    end

    def score_color(score)
      case score
      when 0..20 then "#22c55e"
      when 21..50 then "#f59e0b"
      when 51..75 then "#f97316"
      else "#ef4444"
      end
    end

    def banner_html
      color = VERDICT_COLORS[@email.verdict] || "#6b7280"
      label = VERDICT_LABELS[@email.verdict] || "DESCONHECIDO"

      <<~HTML
        <div class="banner" style="background: #{color};">
          <div class="score-big">#{@email.final_score}/100</div>
          <div class="verdict-label">#{label}</div>
        </div>
      HTML
    end

    def extract_safety_recommendation
      llm_layer = find_layer("triage_llm")
      return nil unless llm_layer&.details.is_a?(Hash)

      llm_layer.details["safety_recommendation"] || llm_layer.details[:safety_recommendation]
    end

    def safety_recommendation_html
      recommendation = extract_safety_recommendation
      return "" if recommendation.blank?

      css_class = @email.final_score.to_i <= 20 ? "safe-notice" : "recommendation"

      <<~HTML
        <div class="#{css_class}">
          <strong>Recomenda&ccedil;&atilde;o:</strong> #{h recommendation}
        </div>
      HTML
    end

    def collect_critical_alerts
      alerts = []

      url_layer = find_layer("triage_url_scan")
      if url_layer&.details.is_a?(Hash)
        details = url_layer.details
        if (details["urlhaus_malicious_count"] || details[:urlhaus_malicious_count]).to_i.positive?
          alerts << "URL(s) confirmada(s) como maliciosa(s) pelo URLhaus"
        end

        Array(details["virustotal"] || details[:virustotal]).each do |vt|
          detections = (vt["detections"] || vt[:detections]).to_i
          next if detections.zero?
          url = vt["url"] || vt[:url]
          alerts << "URL sinalizada pelo VirusTotal: #{safe_url_text(url)} (#{detections} detecções)"
        end
      end

      file_layer = find_layer("triage_file_scan")
      if file_layer&.details.is_a?(Hash)
        Array(file_layer.details["attachments"] || file_layer.details[:attachments]).each do |att|
          detections = (att["detection_count"] || att[:detection_count]).to_i
          next if detections.zero?
          filename = att["filename"] || att[:filename]
          alerts << "Arquivo malicioso: #{filename} (#{detections} detecções no VirusTotal)"
        end
      end

      alerts
    end

    def critical_alerts_html
      alerts = collect_critical_alerts
      return "" if alerts.empty?

      items = alerts.map do |alert|
        "<div class=\"critical-alert\"><strong>\u{1F6A8} ALERTA:</strong> #{h alert}</div>"
      end.join("\n")

      "<div class=\"section\">#{items}</div>"
    end

    def url_scan_html
      url_layer = find_layer("triage_url_scan")
      return "" unless url_layer

      details = url_layer.details || {}
      color = score_color(url_layer.score)

      url_items = []

      # URLhaus results
      Array(details["urlhaus"] || details[:urlhaus]).each do |entry|
        url = entry["url"] || entry[:url]
        malicious = entry["malicious"] || entry[:malicious]
        status_badge = malicious ? "<span style=\"color:#ef4444;font-weight:600;\">MALICIOSA</span>" : "<span style=\"color:#22c55e;\">OK</span>"
        url_items << "<li><span class=\"url-safe\">#{safe_url(url)}</span> #{status_badge}</li>"
      end

      # VirusTotal results (avoid duplicate URLs already shown by URLhaus)
      urlhaus_urls = Array(details["urlhaus"] || details[:urlhaus]).map { |e| e["url"] || e[:url] }
      Array(details["virustotal"] || details[:virustotal]).each do |entry|
        url = entry["url"] || entry[:url]
        next if urlhaus_urls.include?(url)
        detections = (entry["detections"] || entry[:detections]).to_i
        status_badge = detections > 0 ? "<span style=\"color:#ef4444;font-weight:600;\">#{detections} detec&ccedil;&otilde;es</span>" : "<span style=\"color:#22c55e;\">OK</span>"
        url_items << "<li><span class=\"url-safe\">#{safe_url(url)}</span> #{status_badge}</li>"
      end

      urls_html = url_items.any? ? "<ul class=\"findings\">#{url_items.join}</ul>" : ""

      <<~HTML
        <div class="section">
          <h3>Verifica&ccedil;&atilde;o de URLs</h3>
          <div class="layer">
            <table class="layer-header"><tr>
              <td>URLs Verificadas</td>
              <td class="layer-score" style="color: #{color};">#{url_layer.score}/100</td>
            </tr></table>
            <div class="score-bar">
              <div class="score-fill" style="width: #{url_layer.score}%; background: #{color};"></div>
            </div>
            <div class="layer-explanation">#{h url_layer.explanation}</div>
            #{urls_html}
          </div>
        </div>
      HTML
    end

    def file_scan_html
      file_layer = find_layer("triage_file_scan")
      return "" unless file_layer

      details = file_layer.details || {}
      color = score_color(file_layer.score)

      file_items = Array(details["attachments"] || details[:attachments]).map do |att|
        filename = att["filename"] || att[:filename]
        malicious = att["malicious"] || att[:malicious]
        detections = (att["detection_count"] || att[:detection_count]).to_i
        status_badge = if malicious
          "<span style=\"color:#ef4444;font-weight:600;\">#{detections} detec&ccedil;&otilde;es</span>"
        else
          "<span style=\"color:#22c55e;\">OK</span>"
        end
        "<li>#{h filename} #{status_badge}</li>"
      end

      files_html = file_items.any? ? "<ul class=\"findings\">#{file_items.join}</ul>" : ""

      <<~HTML
        <div class="section">
          <h3>Verifica&ccedil;&atilde;o de Arquivos</h3>
          <div class="layer">
            <table class="layer-header"><tr>
              <td>Arquivos Verificados</td>
              <td class="layer-score" style="color: #{color};">#{file_layer.score}/100</td>
            </tr></table>
            <div class="score-bar">
              <div class="score-fill" style="width: #{file_layer.score}%; background: #{color};"></div>
            </div>
            <div class="layer-explanation">#{h file_layer.explanation}</div>
            #{files_html}
          </div>
        </div>
      HTML
    end

    def llm_assessment_html
      return "" if @llm_verdicts.empty?

      rows = @llm_verdicts.map do |v|
        color = score_color(v.score || 0)
        <<~HTML
          <div class="layer">
            <table class="layer-header"><tr>
              <td>Avalia&ccedil;&atilde;o por IA</td>
              <td class="layer-score" style="color: #{color};">#{v.score}/100</td>
            </tr></table>
            <div class="layer-explanation">#{h v.reasoning}</div>
          </div>
        HTML
      end.join

      <<~HTML
        <div class="section">
          <h3>Avalia&ccedil;&atilde;o por IA</h3>
          #{rows}
        </div>
      HTML
    end

    def score_breakdown_html
      rows = @layers.map do |layer|
        color = score_color(layer.score)
        <<~HTML
          <div class="layer">
            <table class="layer-header"><tr>
              <td>#{h layer_label(layer.layer_name)}</td>
              <td class="layer-score" style="color: #{color};">#{layer.score}/100</td>
            </tr></table>
            <div class="layer-explanation">Confian&ccedil;a: #{(layer.confidence * 100).round}% | Peso: #{(layer.weight * 100).round}%</div>
          </div>
        HTML
      end.join

      <<~HTML
        <div class="section">
          <h3>Detalhamento da Pontua&ccedil;&atilde;o</h3>
          #{rows}
        </div>
      HTML
    end
  end
end
