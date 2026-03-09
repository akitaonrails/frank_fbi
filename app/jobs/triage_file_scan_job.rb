class TriageFileScanJob < ApplicationJob
  queue_as :external_api

  def perform(email_id)
    email = Email.find(email_id)
    Triage::FileScanAnalyzer.new(email).analyze
    email.pipeline_orchestrator.advance(email)
  rescue => e
    mark_layer_failed(email_id, "triage_file_scan", e)
    email.pipeline_orchestrator.advance(email) if email
    raise
  end
end
