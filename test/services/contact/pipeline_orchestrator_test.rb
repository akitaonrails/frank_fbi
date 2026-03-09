require "test_helper"

class Contact::PipelineOrchestratorTest < ActiveSupport::TestCase
  include ActiveJob::TestHelper

  setup do
    @email = create(:email, :contact_triage)
  end

  test "advance enqueues url_scan and file_scan jobs" do
    assert_enqueued_with(job: TriageUrlScanJob, args: [@email.id]) do
      assert_enqueued_with(job: TriageFileScanJob, args: [@email.id]) do
        Contact::PipelineOrchestrator.advance(@email)
      end
    end
  end

  test "advance does not enqueue triage_llm job" do
    Contact::PipelineOrchestrator.advance(@email)

    assert_no_enqueued_jobs(only: TriageLlmJob)
  end

  test "advance enqueues score aggregation when both scans completed" do
    @email.analysis_layers.create!(layer_name: "triage_url_scan", weight: 0.40, score: 0, confidence: 0.8, status: "completed", explanation: "OK")
    @email.analysis_layers.create!(layer_name: "triage_file_scan", weight: 0.30, score: 0, confidence: 0.3, status: "completed", explanation: "OK")

    assert_enqueued_with(job: TriageScoreAggregationJob, args: [@email.id]) do
      Contact::PipelineOrchestrator.advance(@email)
    end
  end

  test "advance does not enqueue score aggregation when only one scan completed" do
    @email.analysis_layers.create!(layer_name: "triage_url_scan", weight: 0.40, score: 0, confidence: 0.8, status: "completed", explanation: "OK")

    Contact::PipelineOrchestrator.advance(@email)

    assert_no_enqueued_jobs(only: TriageScoreAggregationJob)
  end

  test "advance does nothing for completed email" do
    @email.update!(status: "completed", final_score: 5, verdict: "legitimate")

    assert_no_enqueued_jobs do
      Contact::PipelineOrchestrator.advance(@email)
    end
  end

  test "failed scan layers still allow pipeline to proceed" do
    @email.analysis_layers.create!(layer_name: "triage_url_scan", weight: 0.40, status: "failed", details: { error: "timeout" })
    @email.analysis_layers.create!(layer_name: "triage_file_scan", weight: 0.30, score: 0, confidence: 0.3, status: "completed", explanation: "OK")

    assert_enqueued_with(job: TriageScoreAggregationJob, args: [@email.id]) do
      Contact::PipelineOrchestrator.advance(@email)
    end
  end

  test "pipeline_layer_names returns contact triage layers" do
    assert_equal %w[triage_url_scan triage_file_scan], @email.pipeline_layer_names
  end

  test "start_from_beginning sets status to analyzing" do
    @email.update!(status: "pending")

    Contact::PipelineOrchestrator.new(@email).start_from_beginning

    assert_equal "analyzing", @email.reload.status
  end
end
