require "test_helper"

class Triage::ReportRendererTest < ActiveSupport::TestCase
  setup do
    @email = create(:email, :messenger_triage, :completed,
      final_score: 45,
      verdict: "suspicious_likely_ok")

    @email.analysis_layers.create!(
      layer_name: "triage_url_scan",
      weight: 0.40,
      score: 30,
      confidence: 0.8,
      status: "completed",
      explanation: "Verificou 3 URLs — nenhuma ameaça detectada.",
      details: {
        urlhaus: [
          { url: "https://evil-phishing-site.com/very-long-path/login?param=value&other=data", malicious: false }
        ],
        virustotal: [
          { url: "https://safe-site.com", malicious: false, detections: 0 }
        ],
        urlhaus_malicious_count: 0
      }
    )

    @email.analysis_layers.create!(
      layer_name: "triage_file_scan",
      weight: 0.30,
      score: 0,
      confidence: 0.3,
      status: "completed",
      explanation: "Nenhum anexo encontrado na mensagem.",
      details: { attachments: [] }
    )

    @email.analysis_layers.create!(
      layer_name: "triage_llm",
      weight: 0.30,
      score: 50,
      confidence: 0.7,
      status: "completed",
      explanation: "Conteúdo com indicadores suspeitos moderados.",
      details: { safety_recommendation: "Não clique em links de remetentes desconhecidos." }
    )
  end

  test "HTML report contains no clickable links (no <a href= tags)" do
    renderer = Triage::ReportRenderer.new(@email)
    html = renderer.to_html

    assert_no_match(/<a\s+href=/i, html,
      "Triage report HTML must NOT contain clickable <a href=> links for URLs")
  end

  test "HTML report uses url-safe class for URL display" do
    renderer = Triage::ReportRenderer.new(@email)
    html = renderer.to_html

    assert_includes html, "url-safe"
  end

  test "HTML report contains verdict banner" do
    renderer = Triage::ReportRenderer.new(@email)
    html = renderer.to_html

    assert_includes html, "55/100"
    assert_includes html, "PROVAVELMENTE SEGURO"
  end

  test "HTML report contains safety recommendation" do
    renderer = Triage::ReportRenderer.new(@email)
    html = renderer.to_html

    assert_match(/Recomenda/, html)
  end

  test "HTML report contains score breakdown" do
    renderer = Triage::ReportRenderer.new(@email)
    html = renderer.to_html

    assert_match(/Verifica.*URLs/i, html)
    assert_match(/Verifica.*Arquivos/i, html)
  end

  test "text report contains verdict and score" do
    renderer = Triage::ReportRenderer.new(@email)
    text = renderer.to_text

    assert_includes text, "55/100"
    assert_includes text, "PROVAVELMENTE SEGURO"
    assert_includes text, "TRIAGEM DE MENSAGEM"
  end

  test "text report contains recommendation" do
    renderer = Triage::ReportRenderer.new(@email)
    text = renderer.to_text

    assert_match(/RECOMENDAÇÃO/, text)
  end

  test "long URLs are truncated in HTML" do
    long_url = "https://evil-phishing-site.com/#{'a' * 100}/path/to/phish"
    @email.analysis_layers.find_by(layer_name: "triage_url_scan").update!(
      details: {
        urlhaus: [{ url: long_url, malicious: true }],
        virustotal: [],
        urlhaus_malicious_count: 1
      }
    )

    renderer = Triage::ReportRenderer.new(@email)
    html = renderer.to_html

    assert_includes html, "..."
    assert_no_match(/<a\s+href=/i, html)
  end

  test "HTML report uses proper triage labels not fraud labels" do
    renderer = Triage::ReportRenderer.new(@email)
    html = renderer.to_html

    assert_match(/Triagem de Mensagens/i, html)
  end
end
