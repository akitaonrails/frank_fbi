class ScreenshotCaptureJob < ApplicationJob
  queue_as :external_api

  # No retries — best-effort enrichment. Errors are caught internally
  # and the pipeline always advances.

  def perform(email_id)
    email = Email.find(email_id)
    ev_layer = email.analysis_layers.find_by!(layer_name: "entity_verification")

    urls = extract_urls(ev_layer)
    screenshots = {}

    if urls.any?
      begin
        screenshots = ScreenshotCapturer.new(urls).capture
      rescue => e
        Rails.logger.warn("ScreenshotCaptureJob failed for email #{email_id}: #{e.message}")
      end
    end

    # Always mark as completed so the pipeline isn't blocked
    ev_layer.with_lock do
      details = ev_layer.reload.details || {}
      details["screenshots"] = screenshots
      details["screenshots_status"] = "completed"
      ev_layer.update!(details: details)
    end

    Analysis::PipelineOrchestrator.advance(email)
  rescue => e
    # On any failure (RecordNotFound, crash, etc.), try to unblock the pipeline
    Rails.logger.warn("ScreenshotCaptureJob error for email #{email_id}: #{e.message}")
    mark_screenshots_failed(email_id)
    begin
      email = Email.find_by(id: email_id)
      Analysis::PipelineOrchestrator.advance(email) if email
    rescue => advance_error
      Rails.logger.error("ScreenshotCaptureJob: advance also failed for email #{email_id}: #{advance_error.message}")
    end
  end

  private

  def extract_urls(ev_layer)
    reference_links = ev_layer.details&.dig("reference_links") || []
    reference_links.filter_map { |link| link["url"] || link[:url] }
  end

  def mark_screenshots_failed(email_id)
    email = Email.find_by(id: email_id)
    return unless email

    ev_layer = email.analysis_layers.find_by(layer_name: "entity_verification")
    return unless ev_layer
    return unless ev_layer.details&.dig("screenshots_status") == "pending"

    ev_layer.with_lock do
      details = ev_layer.reload.details || {}
      details["screenshots_status"] = "failed"
      ev_layer.update!(details: details)
    end
  rescue => e
    Rails.logger.error("ScreenshotCaptureJob: mark_screenshots_failed error: #{e.message}")
  end
end
