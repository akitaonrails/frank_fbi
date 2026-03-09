class ExternalApiAnalysisJob < ApplicationJob
  queue_as :external_api

  def perform(email_id)
    email = Email.find(email_id)
    Analysis::ExternalApiAnalyzer.new(email).analyze
    Analysis::PipelineOrchestrator.advance(email)
  rescue => e
    mark_layer_failed(email_id, "external_api", e)
    Analysis::PipelineOrchestrator.advance(email) if email
    raise
  end
end
