class ReportRenderer
  VERDICT_COLORS = {
    "legitimate" => "#22c55e",
    "suspicious_likely_ok" => "#f59e0b",
    "suspicious_likely_fraud" => "#f97316",
    "fraudulent" => "#ef4444"
  }.freeze

  VERDICT_LABELS = {
    "legitimate" => "LEGÍTIMO",
    "suspicious_likely_ok" => "SUSPEITO (Provavelmente OK)",
    "suspicious_likely_fraud" => "SUSPEITO (Provável Fraude)",
    "fraudulent" => "FRAUDULENTO"
  }.freeze

  VERDICT_EMOJIS = {
    "legitimate" => "\u2705",
    "suspicious_likely_ok" => "\u26A0\uFE0F",
    "suspicious_likely_fraud" => "\u{1F6A8}",
    "fraudulent" => "\u{1F6D1}"
  }.freeze

  LAYER_LABELS = {
    "content_analysis" => "Análise de Conteúdo",
    "external_api" => "Verificação de URLs e Anexos",
    "header_auth" => "Autenticação do E-mail",
    "sender_reputation" => "Reputação do Remetente",
    "entity_verification" => "Verificação de Identidade",
    "llm_analysis" => "Análise por IA"
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
          .verification-badge { padding: 2px 8px; border-radius: 4px; font-size: 12px; font-weight: 600; }
          .badge-ok { background: #dcfce7; color: #166534; }
          .badge-fail { background: #fef2f2; color: #991b1b; }
          .badge-unknown { background: #f3f4f6; color: #6b7280; }
          .analysis-full { white-space: pre-wrap; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; color: #374151; background: #f9fafb; border-radius: 6px; padding: 12px; }
          .critical-alert { background: #fef2f2; border: 2px solid #ef4444; border-radius: 8px; padding: 12px 16px; margin-bottom: 8px; }
          .critical-alert strong { color: #dc2626; }
          .confidence-warning { background: #fffbeb; border: 2px solid #f59e0b; border-radius: 8px; padding: 12px 16px; margin-bottom: 16px; }
          .confidence-warning strong { color: #d97706; }
          .footer { font-size: 11px; color: #9ca3af; text-align: center; margin-top: 24px; border-top: 1px solid #e5e7eb; padding-top: 12px; }
        </style>
      </head>
      <body>
        #{banner_html}

        #{critical_alerts_html}

        #{confidence_warning_html}

        #{forwarding_notice_html}

        <div class="section">
          <h3>E-mail Analisado</h3>
          <p><strong>De:</strong> #{h @email.from_name} &lt;#{h @email.from_address}&gt;</p>
          <p><strong>Assunto:</strong> #{h @email.subject}</p>
          <p><strong>Data:</strong> #{@email.received_at&.strftime('%d/%m/%Y %H:%M %Z')}</p>
        </div>

        #{llm_summary_html}

        #{content_patterns_html}

        #{key_findings_html}

        #{entity_verification_html}

        #{user_facing_layers_html}

        #{technical_details_html}

        #{full_analysis_html}

        <div class="footer">
          <p>Frank FBI &mdash; Sistema de Análise de Fraude em E-mails</p>
          <p>Esta análise é automatizada e deve ser usada como orientação, não como veredito definitivo.</p>
        </div>
      </body>
      </html>
    HTML
  end

  def to_text
    lines = []
    emoji = VERDICT_EMOJIS[@email.verdict] || ""
    lines << "#{emoji} FRANK FBI - RELATÓRIO DE ANÁLISE DE E-MAIL"
    lines << "=" * 50
    lines << ""
    lines << "VEREDITO: #{VERDICT_LABELS[@email.verdict] || @email.verdict&.upcase}"
    lines << "PONTUAÇÃO: #{@email.final_score}/100"

    # Critical alerts right after score
    alerts = collect_critical_alerts
    if alerts.any?
      lines << ""
      lines << "!!! ALERTA CRÍTICO !!!"
      alerts.each { |a| lines << "  #{a}" }
    end

    # Confidence warning
    aggregate_confidence = calculate_aggregate_confidence
    if aggregate_confidence && aggregate_confidence < 0.5
      lines << ""
      lines << "⚠ AVISO: Confiança agregada baixa (#{(aggregate_confidence * 100).round}%). Resultado pode ser impreciso."
    end

    lines << ""
    lines << "--- E-mail Analisado ---"
    lines << "De: #{@email.from_name} <#{@email.from_address}>"
    lines << "Assunto: #{@email.subject}"
    lines << "Data: #{@email.received_at&.strftime('%d/%m/%Y %H:%M %Z')}"

    if forwarding_notice_text.present?
      lines << ""
      lines << forwarding_notice_text
    end

    # AI verdicts first
    if @llm_verdicts.any?
      lines << ""
      lines << "--- Opinião da IA ---"
      @llm_verdicts.each do |v|
        lines << "  #{v.provider.capitalize}: #{v.score}/100 — #{v.reasoning}"
      end
    end

    # Content patterns from LLM
    patterns = llm_content_patterns
    detected = patterns.select { |_, v| v.positive? }
    if detected.any?
      lines << ""
      lines << "--- Padrões de Conteúdo (detectados pela IA) ---"
      detected.each do |key, count|
        label = CONTENT_PATTERN_LABELS[key] || key.humanize
        lines << "  - #{label}: #{count} ocorrência(s)"
      end
    end

    # Key findings
    findings = aggregate_key_findings
    if findings.any?
      lines << ""
      lines << "--- Principais Descobertas ---"
      findings.each { |f| lines << "  - #{f}" }
    end

    # Entity verification
    ev_layer = find_layer("entity_verification")
    if ev_layer
      lines << ""
      lines << "--- Verificação de Identidade ---"
      lines << "  Pontuação: #{ev_layer.score}/100"
      details = ev_layer.details || {}
      sender_v = details["sender_verified"]
      domain_v = details["domain_verified"]
      lines << "  Remetente verificado: #{verification_text(sender_v)}"
      lines << "  Domínio verificado: #{verification_text(domain_v)}"
      domain_age = details["domain_age_days"]
      domain_registrar = details["domain_registrar"]
      if domain_age
        domain_line = "  Domínio: #{domain_age} dias"
        domain_line += " — #{domain_registrar}" if domain_registrar.present?
        domain_line += " [EM LISTA NEGRA]" if details["domain_blacklisted"]
        lines << domain_line
      end
      mismatches = details["entity_mismatches"] || []
      if mismatches.any?
        lines << "  Divergências:"
        mismatches.each { |m| lines << "    - #{m}" }
      end
      ev_findings = details["key_findings"] || []
      reference_links = details["reference_links"] || []
      if ev_findings.any?
        lines << "  Descobertas:"
        ev_findings.each { |f| lines << "    - #{f}" }
      end
      if reference_links.any?
        lines << "  Links verificados:"
        reference_links.each do |link|
          lines << "    - #{link['label'] || link[:label]} (#{link['platform'] || link[:platform]}): #{link['url'] || link[:url]}"
        end
      end
      summary = details["search_summary"]
      lines << "  Pesquisa: #{summary}" if summary.present?
    end

    # Content and external API (user-facing)
    %w[content_analysis external_api].each do |name|
      layer = find_layer(name)
      next unless layer
      lines << ""
      lines << "--- #{layer_label(name)} ---"
      lines << "  #{layer.score}/100 (confiança: #{(layer.confidence * 100).round}%)"
      lines << "  #{layer.explanation}"
    end

    # Technical details at the bottom
    lines << ""
    lines << "--- Detalhes Técnicos ---"
    %w[header_auth sender_reputation].each do |name|
      layer = find_layer(name)
      next unless layer
      lines << "  #{layer_label(name)}: #{layer.score}/100 — #{layer.explanation}"
    end
    llm_layer = find_layer("llm_analysis")
    if llm_layer
      lines << "  #{layer_label('llm_analysis')}: #{llm_layer.score}/100 — #{llm_layer.explanation}"
    end

    if @email.verdict_explanation.present?
      lines << ""
      lines << "--- Análise Completa ---"
      lines << @email.verdict_explanation
    end

    lines << ""
    lines << "-" * 50
    lines << "Frank FBI - Sistema de Análise de Fraude em E-mails"
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

  def forwarding_mode
    @forwarding_mode ||= ForwardingSourceDetector.new(@email.raw_source).detect[:mode]
  end

  def layer_label(name)
    LAYER_LABELS[name] || name.titleize
  end

  def verification_text(value)
    case value
    when true then "Sim"
    when false then "Não"
    else "Indeterminado"
    end
  end

  def verification_badge(value, label_ok, label_fail)
    case value
    when true
      "<span class=\"verification-badge badge-ok\">#{h label_ok}</span>"
    when false
      "<span class=\"verification-badge badge-fail\">#{h label_fail}</span>"
    else
      "<span class=\"verification-badge badge-unknown\">Indeterminado</span>"
    end
  end

  def llm_content_patterns
    llm_layer = find_layer("llm_analysis")
    return {} unless llm_layer&.details.is_a?(Hash)

    (llm_layer.details["content_patterns"] || llm_layer.details[:content_patterns] || {}).transform_values(&:to_i)
  end

  def calculate_aggregate_confidence
    completed = @layers.select { |l| l.status == "completed" }
    return nil if completed.empty?
    completed.sum(&:confidence) / completed.size.to_f
  end

  def collect_critical_alerts
    alerts = []

    ext_layer = find_layer("external_api")
    if ext_layer&.details
      details = ext_layer.details

      # VirusTotal malicious attachments
      Array(details["attachments"] || details[:attachments]).each do |att|
        detections = (att["detection_count"] || att[:detection_count]).to_i
        next if detections.zero?
        filename = att["filename"] || att[:filename] || "arquivo"
        alerts << "Anexo malicioso detectado: #{filename} (#{detections} detecções no VirusTotal)"
      end

      # URLhaus malicious URLs
      if (details["urlhaus_malicious_count"] || details[:urlhaus_malicious_count]).to_i.positive?
        Array(details["urlhaus"] || details[:urlhaus]).each do |url_entry|
          url = url_entry.is_a?(Hash) ? (url_entry["url"] || url_entry[:url]) : url_entry
          alerts << "URL maliciosa confirmada pelo URLhaus: #{url}" if url
        end
        alerts << "URLhaus confirmou URL(s) maliciosa(s) neste e-mail" if alerts.none? { |a| a.include?("URLhaus") }
      end

      # VirusTotal flagged URLs
      Array(details["virustotal"] || details[:virustotal]).each do |vt|
        detections = (vt["detections"] || vt[:detections]).to_i
        next if detections.zero?
        url = vt["url"] || vt[:url] || "URL desconhecida"
        alerts << "URL sinalizada pelo VirusTotal: #{url} (#{detections} detecções)"
      end
    end

    content_layer = find_layer("content_analysis")
    if content_layer&.details
      details = content_layer.details

      # Dangerous attachments
      Array(details["dangerous_attachments"] || details[:dangerous_attachments]).each do |att|
        filename = att.is_a?(Hash) ? (att["filename"] || att[:filename]) : att
        alerts << "Anexo perigoso detectado: #{filename}" if filename
      end

      # URL text/href mismatches
      Array(details["url_mismatches"] || details[:url_mismatches]).each do |mm|
        if mm.is_a?(Hash)
          display = mm["display_text"] || mm[:display_text] || mm["text"] || mm[:text]
          href = mm["actual_url"] || mm[:actual_url] || mm["href"] || mm[:href]
          alerts << "Link enganoso: texto exibe '#{display}' mas aponta para '#{href}'" if display && href
        else
          alerts << "Divergência entre texto e destino de link detectada"
        end
      end
    end

    rep_layer = find_layer("sender_reputation")
    if rep_layer&.details
      blacklist_results = rep_layer.details["blacklist_results"] || rep_layer.details[:blacklist_results] || {}
      blacklist_results.each do |bl_name, entry|
        value = entry.is_a?(Hash) ? entry : {}
        if value["authoritative_malicious"] || value[:authoritative_malicious]
          alerts << "Remetente em blacklist autoritativa: #{bl_name}"
        end
      end
    end

    alerts
  end

  def critical_alerts_html
    alerts = collect_critical_alerts
    return "" if alerts.empty?

    items = alerts.map do |alert|
      "<div class=\"critical-alert\"><strong>\u{1F6A8} ALERTA CRÍTICO:</strong> #{h alert}</div>"
    end.join("\n")

    <<~HTML
      <div class="section">
        #{items}
      </div>
    HTML
  end

  def confidence_warning_html
    aggregate_confidence = calculate_aggregate_confidence
    return "" unless aggregate_confidence && aggregate_confidence < 0.5

    <<~HTML
      <div class="confidence-warning">
        <strong>⚠ Aviso:</strong> Confiança agregada baixa (#{(aggregate_confidence * 100).round}%). O resultado desta análise pode ser impreciso.
      </div>
    HTML
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

  def llm_summary_html
    return "" if @llm_verdicts.empty?

    rows = @llm_verdicts.map do |v|
      color = score_color(v.score || 0)
      <<~HTML
        <div class="layer">
          <table class="layer-header"><tr>
            <td>#{h v.provider.capitalize} (#{h v.model_id})</td>
            <td class="layer-score" style="color: #{color};">#{v.score}/100</td>
          </tr></table>
          <div class="layer-explanation">#{h v.reasoning}</div>
        </div>
      HTML
    end.join

    <<~HTML
      <div class="section">
        <h3>Opinião da IA</h3>
        #{rows}
      </div>
    HTML
  end

  CONTENT_PATTERN_LABELS = {
    "urgency" => "Urgência/Pressão",
    "financial_fraud" => "Fraude Financeira",
    "pii_request" => "Solicitação de Dados Pessoais",
    "authority_impersonation" => "Impersonação de Autoridade",
    "phishing" => "Phishing"
  }.freeze

  def content_patterns_html
    patterns = llm_content_patterns
    return "" if patterns.empty? || patterns.values.all?(&:zero?)

    items = patterns.select { |_, v| v.positive? }.map do |key, count|
      label = CONTENT_PATTERN_LABELS[key] || key.humanize
      "<li>#{h label}: #{count} ocorrência(s)</li>"
    end.join

    return "" if items.empty?

    <<~HTML
      <div class="section">
        <h3>Padrões de Conteúdo (detectados pela IA)</h3>
        <div class="layer">
          <ul class="findings">#{items}</ul>
        </div>
      </div>
    HTML
  end

  def key_findings_html
    findings = aggregate_key_findings
    return "" if findings.empty?

    items = findings.map { |f| "<li>#{h f}</li>" }.join
    <<~HTML
      <div class="section">
        <h3>Principais Descobertas</h3>
        <ul class="findings">#{items}</ul>
      </div>
    HTML
  end

  def entity_verification_html
    ev_layer = find_layer("entity_verification")
    return "" unless ev_layer

    details = ev_layer.details || {}
    sender_v = details["sender_verified"]
    domain_v = details["domain_verified"]
    mismatches = details["entity_mismatches"] || []
    ev_findings = details["key_findings"] || []
    search_summary = details["search_summary"]
    reference_links = details["reference_links"] || []
    domain_age = details["domain_age_days"]
    domain_registrar = details["domain_registrar"]
    domain_blacklisted = details["domain_blacklisted"]
    color = score_color(ev_layer.score)

    # Domain info line
    domain_info_html = ""
    domain_parts = []
    if domain_age
      domain_parts << "#{domain_age} dias"
    end
    if domain_registrar.present?
      domain_parts << h(domain_registrar)
    end
    if domain_parts.any?
      domain_info_html = "<p style=\"font-size:13px;color:#4b5563;margin:4px 0 0;\"><strong>Domínio:</strong> #{domain_parts.join(' — ')}"
      if domain_blacklisted
        domain_info_html += " &nbsp;<span class=\"verification-badge badge-fail\">Em lista negra</span>"
      end
      domain_info_html += "</p>"
    end

    mismatch_html = ""
    if mismatches.any?
      items = mismatches.map { |m| "<li>#{h m}</li>" }.join
      mismatch_html = "<p style=\"font-size:13px;color:#4b5563;margin:4px 0 0;\"><strong>Divergências encontradas:</strong></p><ul class=\"findings\">#{items}</ul>"
    end

    findings_html = ""
    if ev_findings.any?
      items = ev_findings.map { |f| "<li>#{h f}</li>" }.join
      findings_html = "<ul class=\"findings\">#{items}</ul>"
    end

    links_html = ""
    if reference_links.any?
      items = reference_links.map do |link|
        label = link["label"] || link[:label]
        platform = link["platform"] || link[:platform]
        url = link["url"] || link[:url]
        %(<li><a href="#{h url}" target="_blank" rel="noopener noreferrer nofollow">#{h label}</a>#{platform.present? ? " <span style=\"color:#6b7280;\">(#{h platform})</span>" : ""}</li>)
      end.join
      links_html = "<p style=\"font-size:13px;color:#4b5563;margin:4px 0 0;\"><strong>Links verificados:</strong></p><ul class=\"findings\">#{items}</ul>"
    end

    summary_html = ""
    if search_summary.present?
      summary_html = "<p style=\"font-size:12px;color:#6b7280;margin-top:8px;\"><em>#{h search_summary}</em></p>"
    end

    <<~HTML
      <div class="section">
        <h3>Verificação de Identidade</h3>
        <div class="layer">
          <table class="layer-header"><tr>
            <td>Verificação de Identidade</td>
            <td class="layer-score" style="color: #{color};">#{ev_layer.score}/100</td>
          </tr></table>
          <div class="score-bar">
            <div class="score-fill" style="width: #{ev_layer.score}%; background: #{color};"></div>
          </div>
          <p style="margin:8px 0 4px; font-size:13px;">
            Remetente: #{verification_badge(sender_v, "Verificado", "Não verificado")}
            &nbsp;&nbsp;
            Domínio: #{verification_badge(domain_v, "Verificado", "Não verificado")}
          </p>
          #{domain_info_html}
          <div class="layer-explanation">#{h ev_layer.explanation}</div>
          #{mismatch_html}
          #{findings_html}
          #{links_html}
          #{summary_html}
        </div>
      </div>
    HTML
  end

  def user_facing_layers_html
    user_layers = %w[content_analysis external_api]
    layers = user_layers.filter_map { |name| find_layer(name) }
    return "" if layers.empty?

    rows = layers.map do |layer|
      color = score_color(layer.score)
      <<~HTML
        <div class="layer">
          <table class="layer-header"><tr>
            <td>#{h layer_label(layer.layer_name)}</td>
            <td class="layer-score" style="color: #{color};">#{layer.score}/100</td>
          </tr></table>
          <div class="score-bar">
            <div class="score-fill" style="width: #{layer.score}%; background: #{color};"></div>
          </div>
          <div class="layer-explanation">#{h layer.explanation}</div>
        </div>
      HTML
    end.join

    <<~HTML
      <div class="section">
        <h3>Análise Detalhada</h3>
        #{rows}
      </div>
    HTML
  end

  def technical_details_html
    tech_layers = %w[header_auth sender_reputation llm_analysis]
    layers = tech_layers.filter_map { |name| find_layer(name) }
    return "" if layers.empty?

    rows = layers.map do |layer|
      color = score_color(layer.score)
      <<~HTML
        <div class="layer">
          <table class="layer-header"><tr>
            <td>#{h layer_label(layer.layer_name)}</td>
            <td class="layer-score" style="color: #{color};">#{layer.score}/100</td>
          </tr></table>
          <div class="layer-explanation">#{h layer.explanation}</div>
        </div>
      HTML
    end.join

    <<~HTML
      <div class="section">
        <h3>Detalhes Técnicos</h3>
        #{rows}
      </div>
    HTML
  end

  def aggregate_key_findings
    findings = []

    # From LLM verdicts
    @llm_verdicts.each do |v|
      findings.concat(v.key_findings || [])
    end

    # From entity verification
    ev_layer = find_layer("entity_verification")
    if ev_layer&.details
      ev_findings = ev_layer.details["key_findings"] || []
      findings.concat(ev_findings)
    end

    # From layers with high scores (content, external_api)
    %w[content_analysis external_api].each do |name|
      layer = find_layer(name)
      next unless layer && layer.score.to_i > 40
      findings << layer.explanation if layer.explanation.present?
    end

    findings.uniq
  end

  def full_analysis_html
    return "" if @email.verdict_explanation.blank?

    <<~HTML
      <div class="section">
        <h3>Análise Completa</h3>
        <div class="analysis-full">#{h @email.verdict_explanation}</div>
      </div>
    HTML
  end

  def forwarding_notice_html
    case forwarding_mode
    when "inline_forward"
      <<~HTML
        <div class="section">
          <div class="confidence-warning">
            <strong>Envio inline detectado.</strong>
            Conseguimos analisar o conteúdo, mas os cabeçalhos originais do remetente podem ter sido perdidos.
            Para obter SPF, DKIM, DMARC, cadeia <code>Received</code> e anexos originais com mais fidelidade, reenvie usando <strong>Forward as attachment</strong> no Gmail.
          </div>
        </div>
      HTML
    when "attached_message"
      <<~HTML
        <div class="section">
          <div class="layer" style="border-left: 4px solid #22c55e;">
            <div class="layer-explanation">
              Este e-mail foi encaminhado como anexo <code>.eml</code>. A análise pôde usar a mensagem original com mais fidelidade.
            </div>
          </div>
        </div>
      HTML
    else
      ""
    end
  end

  def forwarding_notice_text
    case forwarding_mode
    when "inline_forward"
      "OBSERVAÇÃO: este e-mail foi encaminhado inline. Conseguimos analisar o conteúdo, mas os cabeçalhos originais podem ter sido perdidos. Para uma análise mais completa, reenvie usando Forward as attachment no Gmail."
    when "attached_message"
      "OBSERVAÇÃO: este e-mail foi encaminhado como anexo .eml. A análise pôde usar a mensagem original com mais fidelidade."
    end
  end

  def score_color(score)
    case score
    when 0..20 then "#22c55e"
    when 21..50 then "#f59e0b"
    when 51..75 then "#f97316"
    else "#ef4444"
    end
  end
end
