require "test_helper"

class Analysis::LlmConsensusBuilderTest < ActiveSupport::TestCase
  test "builds consensus from unanimous verdicts" do
    email = create(:email)
    v1 = create(:llm_verdict, email: email, provider: "anthropic", score: 80, verdict: "fraudulent", confidence: 0.9)
    v2 = create(:llm_verdict, email: email, provider: "openai", score: 85, verdict: "fraudulent", confidence: 0.85)
    v3 = create(:llm_verdict, email: email, provider: "xai", score: 78, verdict: "fraudulent", confidence: 0.8)

    result = Analysis::LlmConsensusBuilder.new([v1, v2, v3]).build

    assert result[:score].between?(78, 85)
    assert_equal "fraudulent", result[:details][:majority_verdict]
    assert result[:confidence] > 0.8
  end

  test "handles split verdicts" do
    email = create(:email)
    v1 = create(:llm_verdict, email: email, provider: "anthropic", score: 70, verdict: "suspicious_likely_fraud", confidence: 0.8)
    v2 = create(:llm_verdict, email: email, provider: "openai", score: 30, verdict: "suspicious_likely_ok", confidence: 0.7)
    v3 = create(:llm_verdict, email: email, provider: "xai", score: 65, verdict: "suspicious_likely_fraud", confidence: 0.75)

    result = Analysis::LlmConsensusBuilder.new([v1, v2, v3]).build

    assert_equal "suspicious_likely_fraud", result[:details][:majority_verdict]
    # Confidence should be lower than unanimous
    assert result[:confidence] < 0.85
  end

  test "aggregates key findings" do
    email = create(:email)
    v1 = create(:llm_verdict, email: email, provider: "anthropic", key_findings: ["Finding A", "Finding B"])
    v2 = create(:llm_verdict, email: email, provider: "openai", key_findings: ["Finding B", "Finding C"])

    result = Analysis::LlmConsensusBuilder.new([v1, v2]).build

    assert result[:details][:key_findings].include?("Finding A")
    assert result[:details][:key_findings].include?("Finding C")
  end

  test "handles two-way tie with more cautious verdict" do
    email = create(:email)
    v1 = create(:llm_verdict, email: email, provider: "anthropic", score: 60, verdict: "suspicious_likely_fraud", confidence: 0.8)
    v2 = create(:llm_verdict, email: email, provider: "openai", score: 40, verdict: "suspicious_likely_ok", confidence: 0.8)

    result = Analysis::LlmConsensusBuilder.new([v1, v2]).build

    # Should pick the more cautious verdict in a tie
    assert_equal "suspicious_likely_fraud", result[:details][:majority_verdict]
  end
end
