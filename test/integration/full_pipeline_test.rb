require "test_helper"

class FullPipelineTest < ActiveSupport::TestCase
  test "deterministic layers correctly identify ATM spam" do
    email = create_email_from_eml("YOUR ATM CARD COMPENSATION PAYMENT !!!!.eml")

    # Run deterministic layers
    header_layer = Analysis::HeaderAuthAnalyzer.new(email).analyze
    content_layer = Analysis::ContentAnalyzer.new(email).analyze

    assert_equal "completed", header_layer.status
    assert_equal "completed", content_layer.status

    # Content should flag this heavily
    assert content_layer.score >= 50, "Content score should be >= 50 for ATM spam, got #{content_layer.score}"

    # Header auth should find issues (Reply-To mismatch, auth issues)
    assert header_layer.score >= 20, "Header score should flag some issues, got #{header_layer.score}"
  end

  test "deterministic layers score legitimate email lower" do
    email = create_email_from_eml("Fale Conosco - Gabriel Delfiol.eml")

    header_layer = Analysis::HeaderAuthAnalyzer.new(email).analyze
    content_layer = Analysis::ContentAnalyzer.new(email).analyze

    combined = (header_layer.score * 0.15 + content_layer.score * 0.20) / 0.35
    assert combined < 50, "Legitimate email combined score should be < 50, got #{combined}"
  end

  test "full scoring with all layers produces correct verdict for spam" do
    email = create_email_from_eml("YOUR ATM CARD COMPENSATION PAYMENT !!!!.eml")

    Analysis::HeaderAuthAnalyzer.new(email).analyze
    Analysis::ContentAnalyzer.new(email).analyze

    # Stub remaining layers
    email.analysis_layers.find_or_create_by!(layer_name: "sender_reputation") do |l|
      l.score = 40
      l.weight = 0.15
      l.confidence = 0.6
      l.explanation = "Domain has no prior history"
      l.status = "completed"
    end

    email.analysis_layers.find_or_create_by!(layer_name: "external_api") do |l|
      l.score = 0
      l.weight = 0.15
      l.confidence = 0.3
      l.explanation = "No URLs to scan"
      l.status = "completed"
    end

    email.analysis_layers.find_or_create_by!(layer_name: "entity_verification") do |l|
      l.score = 80
      l.weight = 0.15
      l.confidence = 0.7
      l.explanation = "Sender claims FBI affiliation but no verifiable presence"
      l.status = "completed"
    end

    email.analysis_layers.find_or_create_by!(layer_name: "llm_analysis") do |l|
      l.score = 90
      l.weight = 0.20
      l.confidence = 0.85
      l.explanation = "LLMs unanimously identify this as fraud"
      l.status = "completed"
    end

    result = Analysis::ScoreAggregator.new(email).aggregate

    assert result[:score] >= 50, "ATM spam final score should be >= 50, got #{result[:score]}"
    assert %w[suspicious_likely_fraud fraudulent].include?(result[:verdict]),
           "Verdict should be suspicious or fraudulent, got #{result[:verdict]}"
  end

  test "report generation after scoring" do
    email = create_email_from_eml("YOUR ATM CARD COMPENSATION PAYMENT !!!!.eml")

    # Run deterministic layers
    Analysis::HeaderAuthAnalyzer.new(email).analyze
    Analysis::ContentAnalyzer.new(email).analyze

    # Stub remaining layers
    %w[sender_reputation external_api entity_verification llm_analysis].each do |name|
      email.analysis_layers.find_or_create_by!(layer_name: name) do |l|
        l.score = 75
        l.weight = AnalysisLayer.default_weight(name)
        l.confidence = 0.7
        l.explanation = "Stubbed for test"
        l.status = "completed"
      end
    end

    Analysis::ScoreAggregator.new(email).aggregate

    renderer = ReportRenderer.new(email)
    html = renderer.to_html
    text = renderer.to_text

    assert html.include?("/100")
    assert text.include?("FRANK FBI")
    assert text.include?("VEREDITO:")
  end
end
