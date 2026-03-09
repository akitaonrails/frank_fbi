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
          .footer { font-size: 11px; color: #9ca3af; text-align: center; margin-top: 24px; border-top: 1px solid #e5e7eb; padding-top: 12px; }
        </style>
      </head>
      <body>
        #{banner_html}

        <div class="section">
          <h3>E-mail Analisado</h3>
          <p><strong>De:</strong> #{h @email.from_name} &lt;#{h @email.from_address}&gt;</p>
          <p><strong>Assunto:</strong> #{h @email.subject}</p>
          <p><strong>Data:</strong> #{@email.received_at&.strftime('%d/%m/%Y %H:%M %Z')}</p>
        </div>

        #{llm_summary_html}

        #{key_findings_html}

        #{entity_verification_html}

        #{user_facing_layers_html}

        #{technical_details_html}

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
    lines << ""
    lines << "--- E-mail Analisado ---"
    lines << "De: #{@email.from_name} <#{@email.from_address}>"
    lines << "Assunto: #{@email.subject}"
    lines << "Data: #{@email.received_at&.strftime('%d/%m/%Y %H:%M %Z')}"

    # AI verdicts first
    if @llm_verdicts.any?
      lines << ""
      lines << "--- Opinião da IA ---"
      @llm_verdicts.each do |v|
        lines << "  #{v.provider.capitalize}: #{v.score}/100 — #{v.reasoning}"
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
      if ev_findings.any?
        lines << "  Descobertas:"
        ev_findings.each { |f| lines << "    - #{f}" }
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

    findings.uniq.first(10)
  end

  def score_color(score)
    case score
    when 0..25 then "#22c55e"
    when 26..50 then "#f59e0b"
    when 51..75 then "#f97316"
    else "#ef4444"
    end
  end
end
