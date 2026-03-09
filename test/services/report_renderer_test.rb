require "test_helper"

class ReportRendererTest < ActiveSupport::TestCase
  setup do
    @email = create(:email, :completed, final_score: 85, verdict: "fraudulent", subject: "SCAM EMAIL")
    AnalysisLayer::LAYER_NAMES.each do |name|
      create(:analysis_layer, :completed, email: @email, layer_name: name,
             score: 80, weight: AnalysisLayer.default_weight(name))
    end
    @email.update!(verdict_explanation: "Pontuação Final: 85/100 — Fraudulent\n\nLinha completa de análise")
  end

  test "generates HTML report" do
    renderer = ReportRenderer.new(@email)
    html = renderer.to_html

    assert_includes html, "85/100"
    assert_includes html, "FRAUDULENTO"
    assert_includes html, "SCAM EMAIL"
    assert_includes html, "Autenticação do E-mail"
    assert_includes html, "Análise Completa"
    assert_includes html, "Linha completa de análise"
  end

  test "generates text report" do
    renderer = ReportRenderer.new(@email)
    text = renderer.to_text

    assert_includes text, "85/100"
    assert_includes text, "FRAUDULENTO"
    assert_includes text, "SCAM EMAIL"
    assert_includes text, "--- Análise Completa ---"
    assert_includes text, "Linha completa de análise"
  end

  test "handles email with LLM verdicts" do
    create(:llm_verdict, email: @email, provider: "anthropic", score: 85, reasoning: "Clear fraud indicators")
    renderer = ReportRenderer.new(@email)
    html = renderer.to_html

    assert_includes html, "Anthropic"
    assert_includes html, "Clear fraud indicators"
  end

  test "entity verification renders safe reference links" do
    entity_layer = @email.analysis_layers.find_by(layer_name: "entity_verification")
    entity_layer.update!(
      details: entity_layer.details.merge(
        "reference_links" => [
          { "label" => "LinkedIn", "url" => "https://www.linkedin.com/in/example/", "platform" => "linkedin" },
          { "label" => "Official", "url" => "https://example.com/team", "platform" => "site_oficial" }
        ]
      )
    )

    html = ReportRenderer.new(@email).to_html
    text = ReportRenderer.new(@email).to_text

    assert_includes html, "https://www.linkedin.com/in/example/"
    assert_includes html, "rel=\"noopener noreferrer nofollow\""
    assert_includes text, "Links verificados:"
    assert_includes text, "https://example.com/team"
  end

  test "inline forwarded email includes resubmission guidance" do
    raw_source = <<~EML
      From: trusted@example.com
      Subject: Fwd: Suspicious message

      ---------- Forwarded message ---------
      From: Scammer <scammer@evil.com>

      Click here now.
    EML
    email = create(:email, :completed, raw_source: raw_source)

    text = ReportRenderer.new(email).to_text

    assert_includes text, "Forward as attachment"
  end

  test "attached original message notes higher fidelity analysis" do
    raw = read_eml("original_msg.eml")
    email = create_email_from_eml("original_msg.eml")
    email.update!(raw_source: raw, verdict_explanation: "Pontuação Final: 85/100")

    text = ReportRenderer.new(email).to_text

    assert_includes text, "encaminhado como anexo .eml"
  end

  test "report warns users not to open highly suspicious attachments directly" do
    content_layer = @email.analysis_layers.find_by(layer_name: "content_analysis")
    content_layer.update!(
      details: content_layer.details.merge(
        "attachment_risks" => [
          {
            "filename" => "invoice.zip",
            "severity" => "suspicious",
            "reason" => "Arquivo compactado pode ocultar executáveis, scripts ou documentos perigosos"
          }
        ]
      )
    )

    html = ReportRenderer.new(@email).to_html
    text = ReportRenderer.new(@email).to_text

    assert_includes html, "Atenção aos anexos"
    assert_includes html, "invoice.zip"
    assert_includes text, "CUIDADO COM ANEXOS"
    assert_includes text, "Não abra esses arquivos diretamente"
  end
end
