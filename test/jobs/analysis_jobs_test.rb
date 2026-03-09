require "test_helper"

class AnalysisJobsTest < ActiveSupport::TestCase
  # -- Queue assignments --

  test "HeaderAuthAnalysisJob queues to analysis" do
    assert_equal "analysis", HeaderAuthAnalysisJob.new.queue_name
  end

  test "ContentAnalysisJob queues to analysis" do
    assert_equal "analysis", ContentAnalysisJob.new.queue_name
  end

  test "SenderReputationAnalysisJob queues to analysis" do
    assert_equal "analysis", SenderReputationAnalysisJob.new.queue_name
  end

  test "ExternalApiAnalysisJob queues to external_api" do
    assert_equal "external_api", ExternalApiAnalysisJob.new.queue_name
  end

  test "LlmAnalysisJob queues to llm" do
    assert_equal "llm", LlmAnalysisJob.new.queue_name
  end

  test "ScoreAggregationJob queues to default" do
    assert_equal "default", ScoreAggregationJob.new.queue_name
  end

  test "ReportGenerationJob queues to default" do
    assert_equal "default", ReportGenerationJob.new.queue_name
  end

  test "ReportDeliveryJob queues to default" do
    assert_equal "default", ReportDeliveryJob.new.queue_name
  end

  test "EmailParsingJob queues to default" do
    assert_equal "default", EmailParsingJob.new.queue_name
  end

  # -- HeaderAuthAnalysisJob --

  test "HeaderAuthAnalysisJob runs analyzer and advances pipeline" do
    email = create(:email)

    HeaderAuthAnalysisJob.perform_now(email.id)

    layer = email.analysis_layers.find_by(layer_name: "header_auth")
    assert_not_nil layer
    assert_equal "completed", layer.status
  end

  test "HeaderAuthAnalysisJob handles nil headers gracefully" do
    email = create(:email, raw_source: nil, raw_headers: nil)

    # Analyzer handles nil gracefully — should complete without raising
    HeaderAuthAnalysisJob.perform_now(email.id)

    layer = email.analysis_layers.find_by(layer_name: "header_auth")
    assert_not_nil layer
    assert_equal "completed", layer.status
  end

  # -- ContentAnalysisJob --

  test "ContentAnalysisJob runs analyzer and advances pipeline" do
    email = create(:email)

    ContentAnalysisJob.perform_now(email.id)

    layer = email.analysis_layers.find_by(layer_name: "content_analysis")
    assert_not_nil layer
    assert_equal "completed", layer.status
  end

  # -- EmailParsingJob --

  test "EmailParsingJob parses email and starts pipeline" do
    email = create(:email, :pending)

    EmailParsingJob.perform_now(email.id)

    email.reload
    assert_equal "analyzing", email.status
  end

  test "EmailParsingJob skips non-pending emails" do
    email = create(:email, status: "analyzing")

    EmailParsingJob.perform_now(email.id)

    # Should not change status
    assert_equal "analyzing", email.reload.status
  end

  # -- ScoreAggregationJob --

  test "ScoreAggregationJob aggregates and triggers report generation" do
    email = create(:email)
    AnalysisLayer::LAYER_NAMES.each do |name|
      create(:analysis_layer, :completed, email: email, layer_name: name,
             score: 80, weight: AnalysisLayer.default_weight(name), confidence: 0.9)
    end

    ScoreAggregationJob.perform_now(email.id)

    email.reload
    assert_not_nil email.final_score
    assert_not_nil email.verdict
  end

  test "ScoreAggregationJob skips already scored emails" do
    email = create(:email, final_score: 50, verdict: "suspicious_likely_ok")

    # Should return early without error
    ScoreAggregationJob.perform_now(email.id)

    assert_equal 50, email.reload.final_score
  end

  # -- ReportGenerationJob --

  test "ReportGenerationJob generates report HTML and text" do
    email = create(:email, final_score: 75, verdict: "suspicious_likely_fraud",
                   verdict_explanation: "Test explanation", analyzed_at: Time.current)
    AnalysisLayer::LAYER_NAMES.each do |name|
      create(:analysis_layer, :completed, email: email, layer_name: name,
             score: 75, weight: AnalysisLayer.default_weight(name), confidence: 0.8)
    end

    ReportGenerationJob.perform_now(email.id)

    report = email.analysis_report
    assert_not_nil report
    assert_equal "generated", report.status
    assert report.report_html.include?("/100")
    assert report.report_text.include?("FRANK FBI")
  end

  # -- mark_layer_failed shared behavior --

  test "mark_layer_failed creates failed layer record" do
    email = create(:email)
    # Pre-create the layer so find_or_initialize_by finds it with valid weight
    create(:analysis_layer, :header_auth, email: email)
    error = StandardError.new("test error")

    job = HeaderAuthAnalysisJob.new
    job.send(:mark_layer_failed, email.id, "header_auth", error)

    layer = email.analysis_layers.find_by(layer_name: "header_auth")
    assert_not_nil layer
    assert_equal "failed", layer.status
    assert_equal "test error", layer.details["error"]
  end

  test "mark_layer_failed handles missing email gracefully" do
    error = StandardError.new("test error")
    job = HeaderAuthAnalysisJob.new

    # Should not raise with non-existent email
    assert_nothing_raised do
      job.send(:mark_layer_failed, -1, "header_auth", error)
    end
  end
end
