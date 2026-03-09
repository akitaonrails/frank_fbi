module Contact
  class ReportRenderer
    VERDICT_COLORS = {
      "legitimate" => "#22c55e",
      "suspicious_likely_ok" => "#f59e0b",
      "suspicious_likely_fraud" => "#f97316",
      "fraudulent" => "#ef4444"
    }.freeze

    VERDICT_LABELS = {
      "legitimate" => "SEGURO",
      "suspicious_likely_ok" => "ATENÇÃO",
      "suspicious_likely_fraud" => "SUSPEITO",
      "fraudulent" => "PERIGOSO"
    }.freeze

    VERDICT_EMOJIS = {
      "legitimate" => "\u2705",
      "suspicious_likely_ok" => "\u26A0\uFE0F",
      "suspicious_likely_fraud" => "\u{1F6A8}",
      "fraudulent" => "\u{1F6D1}"
    }.freeze

    # Common contact form field patterns (Portuguese and English)
    CONTACT_PATTERNS = {
      name: /(?:^|\n)\s*(?:Nome|Name|Nombre)\s*:\s*(.+)/i,
      email: /(?:^|\n)\s*(?:E-?mail|Email|Correo)\s*:\s*(\S+@\S+)/i,
      phone: /(?:^|\n)\s*(?:Telefone|Phone|Tel|Celular|WhatsApp|Fone)\s*:\s*(.+)/i,
      company: /(?:^|\n)\s*(?:Empresa|Company|Organiza[çc][ãa]o)\s*:\s*(.+)/i,
      subject: /(?:^|\n)\s*(?:Assunto|Subject|Motivo)\s*:\s*(.+)/i,
      message: /(?:^|\n)\s*(?:Mensagem|Message|Descri[çc][ãa]o|Coment[áa]rio)\s*:\s*([\s\S]+?)(?=\n\s*(?:Nome|Name|E-?mail|Telefone|Phone|Empresa|Company|Assunto|Subject|--|$))/i
    }.freeze

    def initialize(email)
      @email = email
      @layers = email.analysis_layers.order(:layer_name)
      @contact_info = extract_contact_info
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
            .banner-title { font-size: 18px; font-weight: 600; }
            .banner-subtitle { font-size: 13px; margin-top: 4px; opacity: 0.9; }
            .section { margin-bottom: 16px; }
            .section h3 { font-size: 14px; color: #6b7280; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 8px; border-bottom: 1px solid #e5e7eb; padding-bottom: 4px; }
            .contact-card { background: #f9fafb; border-radius: 8px; padding: 16px; border-left: 4px solid #3b82f6; }
            .contact-field { margin-bottom: 8px; }
            .contact-label { font-weight: 600; color: #374151; display: inline-block; min-width: 80px; }
            .contact-value { color: #1f2937; }
            .contact-message { margin-top: 12px; padding: 12px; background: white; border-radius: 6px; border: 1px solid #e5e7eb; white-space: pre-wrap; font-size: 13px; color: #374151; }
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
            .safe-notice { background: #f0fdf4; border: 2px solid #22c55e; border-radius: 8px; padding: 12px 16px; margin-bottom: 16px; }
            .safe-notice strong { color: #166534; }
            .critical-alert { background: #fef2f2; border: 2px solid #ef4444; border-radius: 8px; padding: 12px 16px; margin-bottom: 8px; }
            .critical-alert strong { color: #dc2626; }
            .footer { font-size: 11px; color: #9ca3af; text-align: center; margin-top: 24px; border-top: 1px solid #e5e7eb; padding-top: 12px; }
          </style>
        </head>
        <body>
          #{banner_html}

          #{critical_alerts_html}

          #{safety_notice_html}

          #{contact_info_html}

          #{original_email_html}

          #{url_scan_html}

          #{file_scan_html}

          <div class="footer">
            <p>Frank FBI &mdash; Triagem de Contato (Dom&iacute;nio Confi&aacute;vel)</p>
            <p>URLs e anexos foram verificados automaticamente.</p>
          </div>
        </body>
        </html>
      HTML
    end

    def to_text
      lines = []
      emoji = VERDICT_EMOJIS[@email.verdict] || ""
      label = VERDICT_LABELS[@email.verdict] || "DESCONHECIDO"
      lines << "#{emoji} FRANK FBI - TRIAGEM DE CONTATO"
      lines << "=" * 50
      lines << ""
      lines << "VERIFICAÇÃO: #{label}"

      # Critical alerts
      alerts = collect_critical_alerts
      if alerts.any?
        lines << ""
        lines << "!!! ALERTA !!!"
        alerts.each { |a| lines << "  #{a}" }
      end

      # Safety notice
      if @email.final_score.to_i <= 20 && alerts.empty?
        lines << ""
        lines << "Nenhuma ameaça detectada nas URLs e anexos deste contato."
      end

      # Contact info
      if @contact_info.any?
        lines << ""
        lines << "--- Dados do Contato ---"
        lines << "  Nome: #{@contact_info[:name]}" if @contact_info[:name]
        lines << "  E-mail: #{@contact_info[:email]}" if @contact_info[:email]
        lines << "  Telefone: #{@contact_info[:phone]}" if @contact_info[:phone]
        lines << "  Empresa: #{@contact_info[:company]}" if @contact_info[:company]
        lines << "  Assunto: #{@contact_info[:subject]}" if @contact_info[:subject]
        if @contact_info[:message]
          lines << "  Mensagem:"
          @contact_info[:message].each_line { |l| lines << "    #{l.rstrip}" }
        end
      end

      lines << ""
      lines << "--- E-mail Original ---"
      lines << "De: #{@email.from_name} <#{@email.from_address}>"
      lines << "Assunto: #{@email.subject}"

      # URL scan
      url_layer = find_layer("triage_url_scan")
      if url_layer
        lines << ""
        lines << "--- Verificação de URLs ---"
        lines << "  #{url_layer.explanation}"
      end

      # File scan
      file_layer = find_layer("triage_file_scan")
      if file_layer
        lines << ""
        lines << "--- Verificação de Arquivos ---"
        lines << "  #{file_layer.explanation}"
      end

      lines << ""
      lines << "-" * 50
      lines << "Frank FBI - Triagem de Contato (Domínio Confiável)"
      lines << "URLs e anexos foram verificados automaticamente."
      lines.join("\n")
    end

    private

    def h(text)
      ERB::Util.html_escape(text.to_s)
    end

    def find_layer(name)
      @layers.find { |l| l.layer_name == name }
    end

    def extract_contact_info
      body = @email.body_text.to_s
      info = {}

      CONTACT_PATTERNS.each do |field, pattern|
        match = body.match(pattern)
        info[field] = match[1].strip if match
      end

      # Fallback: use from_name/from_address if no structured fields found
      if info.empty? || (info.keys - [:message]).empty?
        info[:name] ||= @email.from_name if @email.from_name.present?
        info[:email] ||= @email.from_address if @email.from_address.present?
        info[:message] ||= body.strip if body.present?
      end

      info.compact_blank
    end

    # Invert internal score (high=fraud) to display score (high=safe)
    def display_score(internal_score)
      internal_score.present? ? (100 - internal_score) : nil
    end

    def score_color(score)
      case score
      when 80..100 then "#22c55e"  # green (safe)
      when 50..79 then "#f59e0b"   # yellow (caution)
      when 25..49 then "#f97316"   # orange (suspicious)
      else "#ef4444"               # red (dangerous)
      end
    end

    def safe_url(url, max_length = 60)
      url = url.to_s
      return h(url) if url.length <= max_length

      prefix_len = (max_length * 0.6).to_i
      suffix_len = (max_length * 0.3).to_i
      h("#{url[0...prefix_len]}...#{url[-suffix_len..]}")
    end

    def banner_html
      color = VERDICT_COLORS[@email.verdict] || "#3b82f6"
      label = VERDICT_LABELS[@email.verdict] || "CONTATO"

      <<~HTML
        <div class="banner" style="background: #{color};">
          <div class="banner-title">#{label}</div>
          <div class="banner-subtitle">Triagem de Contato &mdash; Dom&iacute;nio Confi&aacute;vel</div>
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
          alerts << "URL sinalizada pelo VirusTotal: #{url} (#{detections} detecções)"
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

    def safety_notice_html
      return "" if collect_critical_alerts.any?
      return "" unless @email.final_score.to_i <= 20

      <<~HTML
        <div class="safe-notice">
          <strong>\u2705 Nenhuma amea&ccedil;a detectada</strong> nas URLs e anexos deste contato.
        </div>
      HTML
    end

    def contact_info_html
      return "" if @contact_info.empty?

      fields = []
      fields << contact_field("Nome", @contact_info[:name]) if @contact_info[:name]
      fields << contact_field("E-mail", @contact_info[:email]) if @contact_info[:email]
      fields << contact_field("Telefone", @contact_info[:phone]) if @contact_info[:phone]
      fields << contact_field("Empresa", @contact_info[:company]) if @contact_info[:company]
      fields << contact_field("Assunto", @contact_info[:subject]) if @contact_info[:subject]

      message_html = ""
      if @contact_info[:message]
        message_html = "<div class=\"contact-message\">#{h @contact_info[:message]}</div>"
      end

      <<~HTML
        <div class="section">
          <h3>Dados do Contato</h3>
          <div class="contact-card">
            #{fields.join("\n")}
            #{message_html}
          </div>
        </div>
      HTML
    end

    def contact_field(label, value)
      "<div class=\"contact-field\"><span class=\"contact-label\">#{h label}:</span> <span class=\"contact-value\">#{h value}</span></div>"
    end

    def original_email_html
      <<~HTML
        <div class="section">
          <h3>E-mail Original</h3>
          <p><strong>De:</strong> #{h @email.from_name} &lt;#{h @email.from_address}&gt;</p>
          <p><strong>Assunto:</strong> #{h @email.subject}</p>
          <p><strong>Dom&iacute;nio:</strong> #{h @email.sender_domain}</p>
        </div>
      HTML
    end

    def url_scan_html
      url_layer = find_layer("triage_url_scan")
      return "" unless url_layer

      details = url_layer.details || {}
      color = score_color(display_score(url_layer.score))

      url_items = []

      Array(details["urlhaus"] || details[:urlhaus]).each do |entry|
        url = entry["url"] || entry[:url]
        malicious = entry["malicious"] || entry[:malicious]
        status_badge = malicious ? "<span style=\"color:#ef4444;font-weight:600;\">MALICIOSA</span>" : "<span style=\"color:#22c55e;\">OK</span>"
        url_items << "<li><span class=\"url-safe\">#{safe_url(url)}</span> #{status_badge}</li>"
      end

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
              <td class="layer-score" style="color: #{color};">#{display_score(url_layer.score)}/100</td>
            </tr></table>
            <div class="score-bar">
              <div class="score-fill" style="width: #{display_score(url_layer.score)}%; background: #{color};"></div>
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
      color = score_color(display_score(file_layer.score))

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
              <td class="layer-score" style="color: #{color};">#{display_score(file_layer.score)}/100</td>
            </tr></table>
            <div class="score-bar">
              <div class="score-fill" style="width: #{display_score(file_layer.score)}%; background: #{color};"></div>
            </div>
            <div class="layer-explanation">#{h file_layer.explanation}</div>
            #{files_html}
          </div>
        </div>
      HTML
    end
  end
end
