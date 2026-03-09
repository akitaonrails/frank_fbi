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
end
