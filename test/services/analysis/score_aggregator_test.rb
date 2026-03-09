require "test_helper"

class Analysis::ScoreAggregatorTest < ActiveSupport::TestCase
  test "calculates weighted average score" do
    email = create(:email)
    create(:analysis_layer, :completed, email: email, layer_name: "header_auth", score: 80, weight: 0.20, confidence: 1.0)
    create(:analysis_layer, :completed, email: email, layer_name: "sender_reputation", score: 60, weight: 0.20, confidence: 0.8)
    create(:analysis_layer, :completed, email: email, layer_name: "content_analysis", score: 90, weight: 0.25, confidence: 1.0)
    create(:analysis_layer, :completed, email: email, layer_name: "external_api", score: 50, weight: 0.20, confidence: 0.5)
    create(:analysis_layer, :completed, email: email, layer_name: "entity_verification", score: 70, weight: 0.05, confidence: 0.7)
    create(:analysis_layer, :completed, email: email, layer_name: "llm_analysis", score: 85, weight: 0.10, confidence: 0.9)

    result = Analysis::ScoreAggregator.new(email).aggregate

    assert result[:score].between?(60, 95)
    assert %w[suspicious_likely_fraud fraudulent].include?(result[:verdict]),
           "Expected fraud-ish verdict, got #{result[:verdict]} (score: #{result[:score]})"
  end

  test "verdict thresholds" do
    email = create(:email)

    # Create a low-scoring set of layers
    AnalysisLayer::LAYER_NAMES.each do |name|
      create(:analysis_layer, :completed, email: email, layer_name: name,
             score: 10, weight: AnalysisLayer.default_weight(name), confidence: 1.0)
    end

    result = Analysis::ScoreAggregator.new(email).aggregate
    assert_equal "legitimate", result[:verdict]
  end

  test "high scores produce fraudulent verdict" do
    email = create(:email)

    AnalysisLayer::LAYER_NAMES.each do |name|
      create(:analysis_layer, :completed, email: email, layer_name: name,
             score: 90, weight: AnalysisLayer.default_weight(name), confidence: 1.0)
    end

    result = Analysis::ScoreAggregator.new(email).aggregate
    assert_equal "fraudulent", result[:verdict]
    assert result[:score] >= 76
  end

  test "confidence affects weighted score" do
    email = create(:email)

    # High score but low confidence should reduce impact
    create(:analysis_layer, :completed, email: email, layer_name: "header_auth", score: 90, weight: 0.20, confidence: 0.2)
    create(:analysis_layer, :completed, email: email, layer_name: "sender_reputation", score: 10, weight: 0.20, confidence: 1.0)
    create(:analysis_layer, :completed, email: email, layer_name: "content_analysis", score: 10, weight: 0.25, confidence: 1.0)
    create(:analysis_layer, :completed, email: email, layer_name: "external_api", score: 10, weight: 0.20, confidence: 1.0)
    create(:analysis_layer, :completed, email: email, layer_name: "entity_verification", score: 10, weight: 0.05, confidence: 1.0)
    create(:analysis_layer, :completed, email: email, layer_name: "llm_analysis", score: 10, weight: 0.10, confidence: 1.0)

    result = Analysis::ScoreAggregator.new(email).aggregate
    # Low-confidence high score should not dominate
    assert result[:score] < 30
  end

  test "updates known domain and sender records" do
    domain = KnownDomain.create!(domain: "test-sender.com", times_seen: 5)
    sender = KnownSender.create!(email_address: "fraud@test-sender.com", known_domain: domain, emails_analyzed: 3)

    email = create(:email, sender_domain: "test-sender.com", from_address: "fraud@test-sender.com")
    AnalysisLayer::LAYER_NAMES.each do |name|
      create(:analysis_layer, :completed, email: email, layer_name: name,
             score: 85, weight: AnalysisLayer.default_weight(name), confidence: 1.0)
    end

    Analysis::ScoreAggregator.new(email).aggregate

    assert_equal 5, domain.reload.times_seen
    assert_equal 3, sender.reload.emails_analyzed
  end

  test "authoritative blacklist hit escalates to 100" do
    email = create(:email)
    create(:analysis_layer, :completed, email: email, layer_name: "header_auth",
           score: 10, weight: AnalysisLayer.default_weight("header_auth"), confidence: 1.0)
    create(:analysis_layer, :completed, email: email, layer_name: "sender_reputation",
           score: 25, weight: AnalysisLayer.default_weight("sender_reputation"), confidence: 1.0,
           details: {
             blacklist_results: {
               "zen.spamhaus.org" => {
                 listed: true,
                 authoritative_malicious: true,
                 categories: ["sbl"]
               }
             }
           })
    create(:analysis_layer, :completed, email: email, layer_name: "content_analysis",
           score: 5, weight: AnalysisLayer.default_weight("content_analysis"), confidence: 1.0)
    create(:analysis_layer, :completed, email: email, layer_name: "external_api",
           score: 0, weight: AnalysisLayer.default_weight("external_api"), confidence: 0.4)
    create(:analysis_layer, :completed, email: email, layer_name: "entity_verification",
           score: 20, weight: AnalysisLayer.default_weight("entity_verification"), confidence: 0.5)
    create(:analysis_layer, :completed, email: email, layer_name: "llm_analysis",
           score: 15, weight: AnalysisLayer.default_weight("llm_analysis"), confidence: 0.5)

    result = Analysis::ScoreAggregator.new(email).aggregate

    assert_equal 100, result[:score]
    assert_equal "fraudulent", result[:verdict]
  end

  test "malicious attachment with high detections escalates to 100" do
    email = create(:email)
    AnalysisLayer::LAYER_NAMES.each do |name|
      details = if name == "external_api"
        {
          attachments_malicious_count: 1,
          attachments: [{ filename: "trojan.exe", detection_count: 9, malicious: true }]
        }
      else
        {}
      end

      create(:analysis_layer, :completed, email: email, layer_name: name,
             score: 5, weight: AnalysisLayer.default_weight(name), confidence: 1.0, details: details)
    end

    result = Analysis::ScoreAggregator.new(email).aggregate

    assert_equal 100, result[:score]
    assert_equal "fraudulent", result[:verdict]
  end

  test "malicious attachment with moderate detections escalates to 95" do
    email = create(:email)
    AnalysisLayer::LAYER_NAMES.each do |name|
      details = if name == "external_api"
        {
          attachments_malicious_count: 1,
          attachments: [{ filename: "dropper.js", detection_count: 4, malicious: true }]
        }
      else
        {}
      end

      create(:analysis_layer, :completed, email: email, layer_name: name,
             score: 5, weight: AnalysisLayer.default_weight(name), confidence: 1.0, details: details)
    end

    result = Analysis::ScoreAggregator.new(email).aggregate

    assert_equal 95, result[:score]
    assert_equal "fraudulent", result[:verdict]
  end

  test "virustotal url detections raise floor without forcing 100" do
    email = create(:email)
    AnalysisLayer::LAYER_NAMES.each do |name|
      details = if name == "external_api"
        {
          virustotal_malicious_count: 1,
          virustotal: [{ url: "https://bad.example", detections: 5, malicious: true }]
        }
      else
        {}
      end

      create(:analysis_layer, :completed, email: email, layer_name: name,
             score: 10, weight: AnalysisLayer.default_weight(name), confidence: 1.0, details: details)
    end

    result = Analysis::ScoreAggregator.new(email).aggregate

    assert_equal 90, result[:score]
    assert_equal "fraudulent", result[:verdict]
  end

  test "verdict explanation lists escalation reasons" do
    email = create(:email)
    AnalysisLayer::LAYER_NAMES.each do |name|
      details = if name == "external_api"
        {
          urlhaus_malicious_count: 1
        }
      else
        {}
      end

      create(:analysis_layer, :completed, email: email, layer_name: name,
             score: 5, weight: AnalysisLayer.default_weight(name), confidence: 1.0, details: details)
    end

    Analysis::ScoreAggregator.new(email).aggregate

    assert_includes email.reload.verdict_explanation, "Gatilhos de escalonamento:"
    assert_includes email.verdict_explanation, "URLhaus confirmou URL maliciosa."
  end
end
