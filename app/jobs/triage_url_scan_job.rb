class TriageUrlScanJob < ApplicationJob
  queue_as :external_api

  def perform(email_id)
    email = Email.find(email_id)
    Triage::UrlScanAnalyzer.new(email).analyze
    Triage::PipelineOrchestrator.advance(email)
  rescue => e
    mark_layer_failed(email_id, "triage_url_scan", e)
    Triage::PipelineOrchestrator.advance(email) if email
    raise
  end
end
