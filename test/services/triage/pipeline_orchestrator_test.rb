require "test_helper"

class Triage::PipelineOrchestratorTest < ActiveSupport::TestCase
  include ActiveJob::TestHelper

  setup do
    @email = create(:email, :messenger_triage)
  end

  test "advance enqueues url_scan and file_scan jobs initially" do
    assert_enqueued_with(job: TriageUrlScanJob, args: [@email.id]) do
      assert_enqueued_with(job: TriageFileScanJob, args: [@email.id]) do
        Triage::PipelineOrchestrator.advance(@email)
      end
    end
  end

  test "advance does not enqueue llm until scans complete" do
    Triage::PipelineOrchestrator.advance(@email)

    assert_no_enqueued_jobs(only: TriageLlmJob)
  end

  test "advance enqueues llm job when both scans completed" do
    @email.analysis_layers.create!(layer_name: "triage_url_scan", weight: 0.40, score: 10, confidence: 0.8, status: "completed", explanation: "OK")
    @email.analysis_layers.create!(layer_name: "triage_file_scan", weight: 0.30, score: 0, confidence: 0.3, status: "completed", explanation: "OK")

    assert_enqueued_with(job: TriageLlmJob, args: [@email.id]) do
      Triage::PipelineOrchestrator.advance(@email)
    end
  end

  test "advance enqueues score aggregation when all layers completed" do
    @email.analysis_layers.create!(layer_name: "triage_url_scan", weight: 0.40, score: 10, confidence: 0.8, status: "completed", explanation: "OK")
    @email.analysis_layers.create!(layer_name: "triage_file_scan", weight: 0.30, score: 0, confidence: 0.3, status: "completed", explanation: "OK")
    @email.analysis_layers.create!(layer_name: "triage_llm", weight: 0.30, score: 30, confidence: 0.7, status: "completed", explanation: "OK")

    assert_enqueued_with(job: TriageScoreAggregationJob, args: [@email.id]) do
      Triage::PipelineOrchestrator.advance(@email)
    end
  end

  test "advance does nothing for completed email" do
    @email.update!(status: "completed", final_score: 50, verdict: "suspicious_likely_ok")

    assert_no_enqueued_jobs do
      Triage::PipelineOrchestrator.advance(@email)
    end
  end

  test "start_from_beginning sets status to analyzing" do
    @email.update!(status: "pending")

    Triage::PipelineOrchestrator.new(@email).start_from_beginning

    assert_equal "analyzing", @email.reload.status
  end

  test "failed scan layers still allow pipeline to proceed" do
    @email.analysis_layers.create!(layer_name: "triage_url_scan", weight: 0.40, status: "failed", details: { error: "timeout" })
    @email.analysis_layers.create!(layer_name: "triage_file_scan", weight: 0.30, score: 0, confidence: 0.3, status: "completed", explanation: "OK")

    assert_enqueued_with(job: TriageLlmJob, args: [@email.id]) do
      Triage::PipelineOrchestrator.advance(@email)
    end
  end

  test "pipeline_layer_names returns triage layers for messenger_triage email" do
    assert_equal %w[triage_url_scan triage_file_scan triage_llm], @email.pipeline_layer_names
  end

  test "pipeline_layer_names returns fraud layers for fraud_analysis email" do
    fraud_email = create(:email)
    assert_equal %w[header_auth sender_reputation content_analysis external_api entity_verification llm_analysis],
      fraud_email.pipeline_layer_names
  end
end
