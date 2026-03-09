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
      search_summary: "Searched for FBI agent and domain",
      reference_links: [
        { label: "LinkedIn Profile", url: "https://www.linkedin.com/in/test-agent/?trk=public", platform: "linkedin" },
        { label: "Official Site", url: "https://asume.gov/about#team", platform: "site_oficial" },
        { label: "Unsafe Redirect", url: "http://evil.example/redirect", platform: "other" }
      ]
    }

    layer = run_with_stubbed_response(response_data.to_json)

    assert_equal "completed", layer.status
    assert_equal "entity_verification", layer.layer_name
    assert_equal 85, layer.score
    assert_in_delta 0.9, layer.confidence, 0.01
    assert_equal 0.10, layer.weight
    assert layer.details["key_findings"].any?
    assert_equal 1, layer.details["reference_links"].size
    assert_equal "https://www.linkedin.com/in/test-agent/", layer.details["reference_links"].first["url"]
  end

  test "handles LLM failure with domain-only fallback" do
    layer = run_with_error("OpenRouter API error")

    assert_equal "completed", layer.status
    # With domain verification fallback, score comes from WHOIS/DNS data
    assert layer.score.between?(0, 100)
    assert layer.details["domain_age_days"].present? || layer.details["key_findings"].any?
  end

  test "handles JSON parse failure" do
    layer = run_with_stubbed_response("This is not valid JSON at all")

    assert_equal "completed", layer.status
    # Falls back to domain-only result since LLM parse failed
    assert layer.score.between?(0, 100)
  end

  test "sets correct weight from WEIGHTS constant" do
    response_data = { score: 50, confidence: 0.5, verdict_summary: "Inconclusive" }
    layer = run_with_stubbed_response(response_data.to_json)

    assert_equal AnalysisLayer::WEIGHTS["entity_verification"], layer.weight
  end

  test "includes domain WHOIS data in details" do
    response_data = { score: 50, confidence: 0.5, verdict_summary: "Inconclusive" }
    layer = run_with_stubbed_response(response_data.to_json)

    # Domain verification always runs, so domain data should be present
    assert layer.details.key?("domain_age_days") || layer.details.key?("domain_whois")
  end

  private

  def stub_domain_verification(analyzer)
    analyzer.define_singleton_method(:verify_domain_directly) do
      {
        domain: "suspicious.com",
        verified: true,
        findings: ["Domínio suspicious.com registrado há 500 dias (Test Registrar)"],
        age_days: 500,
        registrar: "Test Registrar",
        whois: { age_days: 500, registrar: "Test Registrar" },
        blacklisted: false,
        blacklist_hits: 0
      }
    end
  end

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
    analyzer.define_singleton_method(:build_chat) { fake_chat }
    stub_domain_verification(analyzer)
    analyzer.analyze
  end
end
