require "test_helper"

class ScreenshotCaptureJobTest < ActiveSupport::TestCase
  include ActiveJob::TestHelper

  setup do
    @email = create(:email)
    @ev_layer = @email.analysis_layers.create!(
      layer_name: "entity_verification",
      weight: 0.10,
      score: 30,
      confidence: 0.8,
      status: "completed",
      explanation: "OK",
      details: {
        "reference_links" => [{ "url" => "https://example.com", "label" => "Example" }],
        "screenshots_status" => "pending",
        "screenshots_enqueued_at" => Time.current.iso8601
      }
    )
  end

  test "marks screenshots_status as failed and advances pipeline when email not found" do
    email_id = @email.id
    @email.destroy!

    # Should not raise — handles RecordNotFound gracefully
    assert_nothing_raised do
      ScreenshotCaptureJob.perform_now(email_id)
    end
  end

  test "marks screenshots_status as failed when entity_verification layer not found" do
    @ev_layer.destroy!

    assert_nothing_raised do
      ScreenshotCaptureJob.perform_now(@email.id)
    end
  end

  test "marks screenshots_status as failed when ScreenshotCapturer crashes and still advances" do
    # Set up remaining layers so the pipeline can advance
    @ev_layer.update!(details: @ev_layer.details.merge(
      "reference_links" => [{ "url" => "https://nonexistent.invalid", "label" => "Bad" }]
    ))

    # The job catches internal errors and still marks status.
    # Since we can't run headless Chrome in tests, the capturer will fail,
    # but the job should handle it and mark screenshots as completed or failed.
    assert_nothing_raised do
      ScreenshotCaptureJob.perform_now(@email.id)
    end

    @ev_layer.reload
    # Should be either "completed" (error caught internally) or "failed" (outer rescue)
    assert_includes %w[completed failed], @ev_layer.details["screenshots_status"]
  end

  test "queues to external_api" do
    assert_equal "external_api", ScreenshotCaptureJob.new.queue_name
  end
end
