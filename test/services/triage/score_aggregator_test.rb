require "test_helper"

class Triage::ScoreAggregatorTest < ActiveSupport::TestCase
  setup do
    @email = create(:email, :messenger_triage, status: "analyzing")
  end

  test "LLM score is not diluted by empty url_scan and file_scan layers" do
    # Simulate the real scenario: url_scan and file_scan found nothing (score=0),
    # but the LLM detected an obvious scam (score=95, confidence=0.95)
    create(:analysis_layer, :completed,
      email: @email,
      layer_name: "triage_url_scan",
      weight: 0.40,
      score: 0,
      confidence: 0.8,
      explanation: "No URLs found to scan"
    )
    create(:analysis_layer, :completed,
      email: @email,
      layer_name: "triage_file_scan",
      weight: 0.30,
      score: 0,
      confidence: 0.3,
      explanation: "No files found to scan"
    )
    create(:analysis_layer, :completed,
      email: @email,
      layer_name: "triage_llm",
      weight: 0.30,
      score: 95,
      confidence: 0.95,
      explanation: "Obvious phishing scam detected"
    )

    result = Triage::ScoreAggregator.new(@email).aggregate

    # With dampening, the empty layers (score=0) get 0.1x weight,
    # so the LLM's 95 should dominate. Score should be well above 50.
    assert result[:score] >= 76, "Score #{result[:score]} should be >= 76 (fraudulent threshold). LLM detected scam but empty layers diluted it."
    assert_equal "fraudulent", result[:verdict], "Verdict should be 'fraudulent' when LLM detects obvious scam"
  end

  test "dampening factor reduces weight of zero-score layers" do
    aggregator = Triage::ScoreAggregator.new(@email)

    assert_equal 0.1, aggregator.send(:dampening_factor, 0)
    assert_equal 0.1, aggregator.send(:dampening_factor, 10)
    assert_equal 0.4, aggregator.send(:dampening_factor, 20)
    assert_equal 0.7, aggregator.send(:dampening_factor, 50)
    assert_equal 1.0, aggregator.send(:dampening_factor, 75)
    assert_equal 1.0, aggregator.send(:dampening_factor, 100)
  end

  test "all layers with high scores produce fraudulent verdict" do
    create(:analysis_layer, :completed,
      email: @email,
      layer_name: "triage_url_scan",
      weight: 0.40,
      score: 90,
      confidence: 0.9,
      explanation: "Malicious URLs detected"
    )
    create(:analysis_layer, :completed,
      email: @email,
      layer_name: "triage_file_scan",
      weight: 0.30,
      score: 85,
      confidence: 0.8,
      explanation: "Suspicious file detected"
    )
    create(:analysis_layer, :completed,
      email: @email,
      layer_name: "triage_llm",
      weight: 0.30,
      score: 95,
      confidence: 0.95,
      explanation: "Phishing scam"
    )

    result = Triage::ScoreAggregator.new(@email).aggregate

    assert result[:score] >= 76
    assert_equal "fraudulent", result[:verdict]
  end

  test "all layers with low scores produce legitimate verdict" do
    create(:analysis_layer, :completed,
      email: @email,
      layer_name: "triage_url_scan",
      weight: 0.40,
      score: 5,
      confidence: 0.9,
      explanation: "All URLs clean"
    )
    create(:analysis_layer, :completed,
      email: @email,
      layer_name: "triage_file_scan",
      weight: 0.30,
      score: 0,
      confidence: 0.3,
      explanation: "No files to scan"
    )
    create(:analysis_layer, :completed,
      email: @email,
      layer_name: "triage_llm",
      weight: 0.30,
      score: 10,
      confidence: 0.85,
      explanation: "Looks legitimate"
    )

    result = Triage::ScoreAggregator.new(@email).aggregate

    assert result[:score] <= 20
    assert_equal "legitimate", result[:verdict]
  end
end
