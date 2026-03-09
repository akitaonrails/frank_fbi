require "test_helper"

class Analysis::PipelineOrchestratorTest < ActiveSupport::TestCase
  include ActiveJob::TestHelper

  setup do
    @email = create(:email)
  end

  # --- Initial layers ---

  test "advance enqueues header_auth and content_analysis initially" do
    assert_enqueued_with(job: HeaderAuthAnalysisJob, args: [@email.id]) do
      assert_enqueued_with(job: ContentAnalysisJob, args: [@email.id]) do
        Analysis::PipelineOrchestrator.advance(@email)
      end
    end
  end

  # --- Dependent layers ---

  test "advance enqueues sender_reputation after header_auth completes" do
    @email.analysis_layers.create!(layer_name: "header_auth", weight: 0.15, score: 10, confidence: 1.0, status: "completed", explanation: "OK")

    assert_enqueued_with(job: SenderReputationAnalysisJob, args: [@email.id]) do
      Analysis::PipelineOrchestrator.advance(@email)
    end
  end

  test "advance enqueues external_api after content_analysis completes" do
    @email.analysis_layers.create!(layer_name: "content_analysis", weight: 0.15, score: 20, confidence: 1.0, status: "completed", explanation: "OK")

    assert_enqueued_with(job: ExternalApiAnalysisJob, args: [@email.id]) do
      Analysis::PipelineOrchestrator.advance(@email)
    end
  end

  test "advance enqueues entity_verification after header_auth and content_analysis complete" do
    @email.analysis_layers.create!(layer_name: "header_auth", weight: 0.15, score: 10, confidence: 1.0, status: "completed", explanation: "OK")
    @email.analysis_layers.create!(layer_name: "content_analysis", weight: 0.15, score: 20, confidence: 1.0, status: "completed", explanation: "OK")

    assert_enqueued_with(job: EntityVerificationJob, args: [@email.id]) do
      Analysis::PipelineOrchestrator.advance(@email)
    end
  end

  test "advance enqueues llm_analysis when all pre-LLM layers finished" do
    %w[header_auth sender_reputation content_analysis external_api entity_verification].each do |name|
      @email.analysis_layers.create!(layer_name: name, weight: AnalysisLayer.default_weight(name),
        score: 30, confidence: 0.8, status: "completed", explanation: "OK")
    end

    assert_enqueued_with(job: LlmAnalysisJob, args: [@email.id]) do
      Analysis::PipelineOrchestrator.advance(@email)
    end
  end

  # --- enqueue_if_ready skips failed layers ---

  test "enqueue_if_ready does not re-enqueue failed layers" do
    @email.analysis_layers.create!(layer_name: "header_auth", weight: 0.15, status: "failed",
      details: { error: "timeout" })

    Analysis::PipelineOrchestrator.advance(@email)

    # header_auth should NOT be re-enqueued since it failed
    assert_no_enqueued_jobs(only: HeaderAuthAnalysisJob)
  end

  test "enqueue_if_ready does not re-enqueue running layers" do
    @email.analysis_layers.create!(layer_name: "header_auth", weight: 0.15, status: "running")

    Analysis::PipelineOrchestrator.advance(@email)

    assert_no_enqueued_jobs(only: HeaderAuthAnalysisJob)
  end

  # --- Screenshot timeout ---

  test "screenshots_pending returns true when recently enqueued" do
    %w[header_auth sender_reputation content_analysis external_api entity_verification llm_analysis].each do |name|
      @email.analysis_layers.create!(layer_name: name, weight: AnalysisLayer.default_weight(name),
        score: 30, confidence: 0.8, status: "completed", explanation: "OK")
    end
    ev_layer = @email.analysis_layers.find_by(layer_name: "entity_verification")
    ev_layer.update!(details: {
      "reference_links" => [{ "url" => "https://example.com", "label" => "test" }],
      "screenshots_status" => "pending",
      "screenshots_enqueued_at" => Time.current.iso8601
    })

    # All layers complete but screenshots pending — should NOT enqueue score aggregation
    assert_no_enqueued_jobs(only: ScoreAggregationJob) do
      Analysis::PipelineOrchestrator.advance(@email)
    end
  end

  test "screenshots_pending returns false after timeout" do
    %w[header_auth sender_reputation content_analysis external_api entity_verification llm_analysis].each do |name|
      @email.analysis_layers.create!(layer_name: name, weight: AnalysisLayer.default_weight(name),
        score: 30, confidence: 0.8, status: "completed", explanation: "OK")
    end
    ev_layer = @email.analysis_layers.find_by(layer_name: "entity_verification")
    ev_layer.update!(details: {
      "reference_links" => [{ "url" => "https://example.com", "label" => "test" }],
      "screenshots_status" => "pending",
      "screenshots_enqueued_at" => 10.minutes.ago.iso8601
    })

    # Screenshots timed out — pipeline should advance
    assert_enqueued_with(job: ScoreAggregationJob, args: [@email.id]) do
      Analysis::PipelineOrchestrator.advance(@email)
    end

    # Verify status was updated to timed_out
    ev_layer.reload
    assert_equal "timed_out", ev_layer.details["screenshots_status"]
  end

  test "screenshots_pending returns false when no entity_verification layer" do
    @email.pipeline_layer_names.each do |name|
      next if name == "entity_verification"
      @email.analysis_layers.create!(layer_name: name, weight: AnalysisLayer.default_weight(name),
        score: 30, confidence: 0.8, status: "completed", explanation: "OK")
    end
    @email.analysis_layers.create!(layer_name: "entity_verification", weight: 0.10,
      score: 30, confidence: 0.8, status: "completed", explanation: "OK", details: {})

    # No reference_links means no screenshots — should proceed
    assert_enqueued_with(job: ScoreAggregationJob, args: [@email.id]) do
      Analysis::PipelineOrchestrator.advance(@email)
    end
  end

  # --- Completion ---

  test "advance enqueues score aggregation when all layers completed" do
    @email.pipeline_layer_names.each do |name|
      @email.analysis_layers.create!(layer_name: name, weight: AnalysisLayer.default_weight(name),
        score: 30, confidence: 0.8, status: "completed", explanation: "OK")
    end

    assert_enqueued_with(job: ScoreAggregationJob, args: [@email.id]) do
      Analysis::PipelineOrchestrator.advance(@email)
    end
  end

  test "advance does nothing for completed email" do
    @email.update!(status: "completed", final_score: 50, verdict: "suspicious_likely_ok")

    assert_no_enqueued_jobs do
      Analysis::PipelineOrchestrator.advance(@email)
    end
  end

  test "advance does nothing for failed email" do
    @email.update!(status: "failed")

    assert_no_enqueued_jobs do
      Analysis::PipelineOrchestrator.advance(@email)
    end
  end

  test "failed layers still allow pipeline to proceed" do
    %w[header_auth sender_reputation content_analysis external_api].each do |name|
      @email.analysis_layers.create!(layer_name: name, weight: AnalysisLayer.default_weight(name),
        score: 30, confidence: 0.8, status: "completed", explanation: "OK")
    end
    @email.analysis_layers.create!(layer_name: "entity_verification", weight: 0.10,
      status: "failed", details: { error: "timeout" })

    # entity_verification failed, but pre_llm should still be "finished"
    assert_enqueued_with(job: LlmAnalysisJob, args: [@email.id]) do
      Analysis::PipelineOrchestrator.advance(@email)
    end
  end

  test "start_from_beginning sets status to analyzing" do
    @email.update!(status: "pending")

    Analysis::PipelineOrchestrator.new(@email).start_from_beginning

    assert_equal "analyzing", @email.reload.status
  end

  test "pipeline_layer_names returns fraud layers for fraud_analysis email" do
    assert_equal %w[header_auth sender_reputation content_analysis external_api entity_verification llm_analysis],
      @email.pipeline_layer_names
  end
end
