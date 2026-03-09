require "test_helper"

class Contact::ReportRendererTest < ActiveSupport::TestCase
  setup do
    @email = create(:email, :contact_triage, :completed,
      final_score: 5,
      verdict: "legitimate")

    @email.analysis_layers.create!(
      layer_name: "triage_url_scan",
      weight: 0.40,
      score: 0,
      confidence: 0.8,
      status: "completed",
      explanation: "Nenhuma URL encontrada na mensagem.",
      details: { urlhaus: [], virustotal: [], urlhaus_malicious_count: 0 }
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
  end

  test "HTML report contains contact info fields" do
    renderer = Contact::ReportRenderer.new(@email)
    html = renderer.to_html

    assert_includes html, "João Silva"
    assert_includes html, "joao@empresa.com"
    assert_includes html, "(11) 99999-0000"
    assert_includes html, "Dados do Contato"
  end

  test "HTML report contains trusted domain banner" do
    renderer = Contact::ReportRenderer.new(@email)
    html = renderer.to_html

    assert_match(/Triagem de Contato/i, html)
    assert_match(/Confi&aacute;vel/i, html)
  end

  test "HTML report shows safety notice when score is low and no alerts" do
    renderer = Contact::ReportRenderer.new(@email)
    html = renderer.to_html

    assert_match(/Nenhuma amea.*detectada/, html)
  end

  test "HTML report hides safety notice when threats found" do
    @email.analysis_layers.find_by(layer_name: "triage_url_scan").update!(
      score: 80,
      details: {
        urlhaus: [{ url: "https://evil.com", malicious: true }],
        virustotal: [],
        urlhaus_malicious_count: 1
      }
    )

    renderer = Contact::ReportRenderer.new(@email.reload)
    html = renderer.to_html

    assert_no_match(/Nenhuma amea.*detectada/, html)
    assert_match(/ALERTA/, html)
  end

  test "HTML report contains no clickable links for URLs" do
    @email.analysis_layers.find_by(layer_name: "triage_url_scan").update!(
      details: {
        urlhaus: [{ url: "https://some-site.com/path", malicious: false }],
        virustotal: [],
        urlhaus_malicious_count: 0
      }
    )

    renderer = Contact::ReportRenderer.new(@email.reload)
    html = renderer.to_html

    assert_no_match(/<a\s+href=/i, html,
      "Contact report HTML must NOT contain clickable <a href=> links for scanned URLs")
  end

  test "HTML report shows original email info" do
    renderer = Contact::ReportRenderer.new(@email)
    html = renderer.to_html

    assert_includes html, "codeminer42.com"
    assert_includes html, "contact@codeminer42.com"
  end

  test "text report contains contact info" do
    renderer = Contact::ReportRenderer.new(@email)
    text = renderer.to_text

    assert_includes text, "TRIAGEM DE CONTATO"
    assert_includes text, "João Silva"
    assert_includes text, "joao@empresa.com"
    assert_includes text, "(11) 99999-0000"
  end

  test "text report contains safety verdict" do
    renderer = Contact::ReportRenderer.new(@email)
    text = renderer.to_text

    assert_includes text, "SEGURO"
  end

  test "extracts contact info from structured body" do
    renderer = Contact::ReportRenderer.new(@email)
    html = renderer.to_html

    assert_includes html, "Dados do Contato"
    assert_match(/contact-card/, html)
  end

  test "falls back to from_name when no structured contact fields" do
    @email.update!(body_text: "Hello, I am interested in your services. Please contact me.")

    renderer = Contact::ReportRenderer.new(@email)
    html = renderer.to_html

    # Should fall back to from_name
    assert_includes html, "João Silva"
  end

  test "HTML report does not contain fraud-specific elements" do
    renderer = Contact::ReportRenderer.new(@email)
    html = renderer.to_html

    assert_no_match(/Opinião da IA/i, html)
    assert_no_match(/Verificação de Identidade/i, html)
    assert_no_match(/Autenticação do E-mail/i, html)
    assert_no_match(/Reputação do Remetente/i, html)
  end
end
