require "test_helper"

class Analysis::EntityVerificationAnalyzerTest < ActiveSupport::TestCase
  setup do
    @email = create(:email, :spam)

    # Create prerequisite completed layers
    create(:analysis_layer, :completed, :header_auth, email: @email, score: 60)
    create(:analysis_layer, :completed, :content_analysis, email: @email, score: 80)
  end

  test "creates entity_verification layer on success" do
    response_data = {
      score: 85,
      confidence: 0.9,
      verdict_summary: "Sender claims FBI affiliation but no agent by that name exists",
      sender_verified: false,
      domain_verified: false,
      entity_mismatches: ["FBI domain mismatch", "No agent found"],
      key_findings: ["No FBI agent named this exists", "Domain is not FBI.gov"],
      search_summary: "Searched for FBI agent and domain"
    }

    layer = run_with_stubbed_response(response_data.to_json)

    assert_equal "completed", layer.status
    assert_equal "entity_verification", layer.layer_name
    assert_equal 85, layer.score
    assert_in_delta 0.9, layer.confidence, 0.01
    assert_equal 0.15, layer.weight
    assert layer.details["key_findings"].any?
  end

  test "handles LLM failure gracefully" do
    layer = run_with_error("OpenRouter API error")

    assert_equal "completed", layer.status
    assert_equal 50, layer.score
    assert_in_delta 0.2, layer.confidence, 0.01
    assert_includes layer.explanation, "falhou"
  end

  test "handles JSON parse failure" do
    layer = run_with_stubbed_response("This is not valid JSON at all")

    assert_equal "completed", layer.status
    assert_equal 50, layer.score
    assert_in_delta 0.2, layer.confidence, 0.01
  end

  test "sets correct weight from WEIGHTS constant" do
    response_data = { score: 50, confidence: 0.5, verdict_summary: "Inconclusive" }
    layer = run_with_stubbed_response(response_data.to_json)

    assert_equal AnalysisLayer::WEIGHTS["entity_verification"], layer.weight
  end

  private

  # Subclass the analyzer to inject a fake chat object instead of calling RubyLLM
  def run_with_stubbed_response(json_text)
    response = Struct.new(:content, :input_tokens, :output_tokens).new(json_text, 500, 200)
    chat = Object.new
    chat.define_singleton_method(:with_tool) { |_tool| self }
    chat.define_singleton_method(:ask) { |_prompt| response }

    run_analyzer_with_chat(chat)
  end

  def run_with_error(message)
    chat = Object.new
    chat.define_singleton_method(:with_tool) { |_tool| self }
    chat.define_singleton_method(:ask) { |_prompt| raise StandardError, message }

    run_analyzer_with_chat(chat)
  end

  def run_analyzer_with_chat(fake_chat)
    analyzer = Analysis::EntityVerificationAnalyzer.new(@email)
    # Inject fake chat by overriding the private method via a singleton method
    analyzer.define_singleton_method(:build_chat) { fake_chat }
    analyzer.analyze
  end
end
