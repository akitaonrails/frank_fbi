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
          .layer-header { display: flex; justify-content: space-between; font-weight: 600; }
          .layer-score { font-weight: bold; }
          .layer-explanation { font-size: 13px; color: #4b5563; margin-top: 4px; }
          .score-bar { height: 6px; border-radius: 3px; background: #e5e7eb; margin-top: 4px; }
          .score-fill { height: 100%; border-radius: 3px; }
          .findings { padding-left: 20px; margin: 8px 0; }
          .findings li { font-size: 13px; color: #374151; margin-bottom: 4px; }
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

        <div class="section">
          <h3>Detalhamento da Análise</h3>
          #{layers_html}
        </div>

        #{key_findings_html}

        #{llm_summary_html}

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
    lines << ""
    lines << "--- Detalhamento da Análise ---"

    @layers.each do |layer|
      lines << ""
      lines << "#{layer.layer_name.titleize}: #{layer.score}/100 (confiança: #{(layer.confidence * 100).round}%)"
      lines << "  #{layer.explanation}"
    end

    findings = aggregate_key_findings
    if findings.any?
      lines << ""
      lines << "--- Principais Descobertas ---"
      findings.each { |f| lines << "  - #{f}" }
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

  def layers_html
    @layers.map do |layer|
      color = score_color(layer.score)
      <<~HTML
        <div class="layer">
          <div class="layer-header">
            <span>#{h layer.layer_name.titleize}</span>
            <span class="layer-score" style="color: #{color};">#{layer.score}/100</span>
          </div>
          <div class="score-bar">
            <div class="score-fill" style="width: #{layer.score}%; background: #{color};"></div>
          </div>
          <div class="layer-explanation">#{h layer.explanation}</div>
        </div>
      HTML
    end.join
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

  def llm_summary_html
    return "" if @llm_verdicts.empty?

    rows = @llm_verdicts.map do |v|
      color = score_color(v.score || 0)
      <<~HTML
        <div class="layer">
          <div class="layer-header">
            <span>#{h v.provider.capitalize} (#{h v.model_id})</span>
            <span class="layer-score" style="color: #{color};">#{v.score}/100</span>
          </div>
          <div class="layer-explanation">#{h v.reasoning}</div>
        </div>
      HTML
    end.join

    <<~HTML
      <div class="section">
        <h3>Vereditos dos Modelos de IA</h3>
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

    # From layers with high scores
    @layers.select { |l| l.score.to_i > 40 }.each do |layer|
      findings << layer.explanation if layer.explanation.present?
    end

    findings.uniq.first(7)
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
